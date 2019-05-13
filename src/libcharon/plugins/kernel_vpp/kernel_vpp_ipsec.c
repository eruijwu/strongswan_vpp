#include <daemon.h>
#include <utils/debug.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>

#define vl_typedefs
#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs
#undef vl_endianfun

#include "kernel_vpp_ipsec.h"
#include "kernel_vpp_shared.h"

#define PRIO_BASE 384
u32 g_interface=1;
#define VPP_INTERFACE_FEATURE 0
typedef struct private_kernel_vpp_ipsec_t private_kernel_vpp_ipsec_t;

/**
 * Private variables of kernel_vpp_ipsec class.
 */
struct private_kernel_vpp_ipsec_t {

    /**
     * Public interface
     */
    kernel_vpp_ipsec_t public;

//
    /** TRUE if initiator of the exchange creating the SA */
    bool initiator;

    time_t up_time;

    /**
     * our actually used SPI, 0 if unused
     */
    uint32_t my_spi;
    
    /**
     * others used SPI, 0 if unused
     */
    uint32_t other_spi;
//
    /**
     * Next security association database entry ID to allocate
     */
    refcount_t next_sad_id;

    /**
     * Next security policy database entry ID to allocate
     */
    refcount_t next_spd_id;

    /**
     * Mutex to lock access to installed policies
     */
    mutex_t *mutex;

    /**
     * Hash table of instaled SA, as kernel_ipsec_sa_id_t => sa_t
     */
    hashtable_t *sas;

    /**
     * Hash table of security policy databases, as nterface => spd_t
     */
    hashtable_t *spds;

    /**
     * Linked list of installed routes
     */
    linked_list_t *routes;

    /**
     * Next SPI to allocate
     */
    refcount_t nextspi;

    /**
     * Mix value to distribute SPI allocation randomly
     */
    uint32_t mixspi;

    /**
     * Whether to install routes along policies
     */
    bool install_routes;

    bool vpp_interface;//default 0
};

/**
 * Security association entry
 */
typedef struct {
    /** VPP SA ID */
    uint32_t sa_id;
    /** Data required to add/delete SA to VPP */
    vl_api_ipsec_sad_entry_add_del_t *mp;
} sa_t;

/**
 * Security policy database
 */
typedef struct {
    /** VPP SPD ID */
    uint32_t spd_id;
    /** Networking interface ID restricting policy */
    uint32_t sw_if_index;
    /** Policy count for this SPD */
    refcount_t policy_num;
} spd_t;

/**
 * Installed route
 */
typedef struct {
    /** Name of the interface the route is bound to */
    char *if_name;
    /** Gateway of route */
    host_t *gateway;
    /** Destination network of route */
    host_t *dst_net;
    /** Prefix length of dst_net */
    uint8_t prefixlen;
    /** References for route */
    int refs;
} route_entry_t;

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))

CALLBACK(route_equals, bool, route_entry_t *a, va_list args)
{
    host_t *dst_net, *gateway;
    uint8_t *prefixlen;
    char *if_name;

    VA_ARGS_VGET(args, if_name, gateway, dst_net, prefixlen);

    return a->if_name && if_name && streq(a->if_name, if_name) &&
           a->gateway->ip_equals(a->gateway, gateway) &&
           a->dst_net->ip_equals(a->dst_net, dst_net) &&
           a->prefixlen == *prefixlen;
}

/**
 * Clean up a route entry
 */
static void route_destroy(route_entry_t *this)
{
    this->dst_net->destroy(this->dst_net);
    this->gateway->destroy(this->gateway);
    free(this->if_name);
    free(this);
}

/**
 * (Un)-install a single route
 */
static void manage_route(private_kernel_vpp_ipsec_t *this, bool add,
                         traffic_selector_t *dst_ts, host_t *src, host_t *dst)
{
    host_t *dst_net, *gateway;
    uint8_t prefixlen;
    char *if_name;
    route_entry_t *route;
    bool route_exist = FALSE;

    if (dst->is_anyaddr(dst))
    {
        return;
    }
    gateway = charon->kernel->get_nexthop(charon->kernel, dst, -1, NULL, &if_name);
    dst_ts->to_subnet(dst_ts, &dst_net, &prefixlen);
    if (!if_name)
    {
        if (src->is_anyaddr(src))
        {
            return;
        }
        if (!charon->kernel->get_interface(charon->kernel, src, &if_name))
        {
            return;
        }
    }
    route_exist = this->routes->find_first(this->routes, route_equals,
        (void**)&route, if_name, gateway, dst_net, &prefixlen);
    if (add)
    {
        if (route_exist)
        {
            route->refs++;
        }
        else
        {
            DBG2(DBG_KNL, "installing route: %H/%d via %H dev %s",
                 dst_net, prefixlen, gateway, if_name);
            INIT(route,
                .if_name = strdup(if_name),
                .gateway = gateway->clone(gateway),
                .dst_net = dst_net->clone(dst_net),
                .prefixlen = prefixlen,
                .refs = 1,
            );
            this->routes->insert_last(this->routes, route);
            charon->kernel->add_route(charon->kernel,
                 dst_net->get_address(dst_net), prefixlen, dst, NULL, if_name);
        }
    }
    else
    {
        if (!route_exist || --route->refs > 0)
        {
            return;
        }
        DBG2(DBG_KNL, "uninstalling route: %H/%d via %H dev %s",
             dst_net, prefixlen, gateway, if_name);
        this->routes->remove(this->routes, route, NULL);
        route_destroy(route);
        charon->kernel->del_route(charon->kernel, dst_net->get_address(dst_net),
             prefixlen, dst, NULL, if_name);
    }
}

/**
 * Hash function for IPsec SA
 */
static u_int sa_hash(kernel_ipsec_sa_id_t *sa)
{
    return chunk_hash_inc(sa->src->get_address(sa->src),
                          chunk_hash_inc(sa->dst->get_address(sa->dst),
                          chunk_hash_inc(chunk_from_thing(sa->spi),
                          chunk_hash(chunk_from_thing(sa->proto)))));
}

/**
 * Equality function for IPsec SA
 */
static bool sa_equals(kernel_ipsec_sa_id_t *sa, kernel_ipsec_sa_id_t *other_sa)
{
    return sa->src->ip_equals(sa->src, other_sa->src) &&
            sa->dst->ip_equals(sa->dst, other_sa->dst) &&
            sa->spi == other_sa->spi && sa->proto == other_sa->proto;
}

/**
 * Hash function for interface
 */
static u_int interface_hash(char *interface)
{
    return chunk_hash(chunk_from_str(interface));
}

/**
 * Equality function for interface
 */
static bool interface_equals(char *interface1, char *interface2)
{
    return streq(interface1, interface2);
}

/**
 * Map an integer x with a one-to-one function using quadratic residues
 */
static u_int permute(u_int x, u_int p)
{
    u_int qr;

    x = x % p;
    qr = ((uint64_t)x * x) % p;
    if (x <= p / 2)
    {
        return qr;
    }
    return p - qr;
}

/**
 * Initialize seeds for SPI generation
 */
static bool init_spi(private_kernel_vpp_ipsec_t *this)
{
    bool ok = TRUE;
    rng_t *rng;

    rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
    if (!rng)
    {
        return FALSE;
    }
    ok = rng->get_bytes(rng, sizeof(this->nextspi), (uint8_t*)&this->nextspi);
    if (ok)
    {
        ok = rng->get_bytes(rng, sizeof(this->mixspi), (uint8_t*)&this->mixspi);
    }
    rng->destroy(rng);
    return ok;
}

/**
 * Calculate policy priority
 */
static uint32_t calculate_priority(policy_priority_t policy_priority,
                                   traffic_selector_t *src,
                                   traffic_selector_t *dst)
{
    uint32_t priority = PRIO_BASE;
    uint16_t port;
    uint8_t mask, proto;
    host_t *net;

    switch (policy_priority)
    {
        case POLICY_PRIORITY_FALLBACK:
            priority <<= 1;
            /* fall-through */
        case POLICY_PRIORITY_ROUTED:
            priority <<= 1;
            /* fall-through */
        case POLICY_PRIORITY_DEFAULT:
            priority <<= 1;
            /* fall-through */
        case POLICY_PRIORITY_PASS:
            break;
    }
    /* calculate priority based on selector size, small size = high prio */
    src->to_subnet(src, &net, &mask);
    priority -= mask;
    proto = src->get_protocol(src);
    port = net->get_port(net);
    net->destroy(net);

    dst->to_subnet(dst, &net, &mask);
    priority -= mask;
    proto = max(proto, dst->get_protocol(dst));
    port = max(port, net->get_port(net));
    net->destroy(net);

    priority <<= 2; /* make some room for the two flags */
    priority += port ? 0 : 2;
    priority += proto ? 0 : 1;
    return priority;
}

/**
 * Get sw_if_index from interface name
 */
static uint32_t get_sw_if_index(char *interface)
{
    char *out = NULL;
    int out_len;
    vl_api_sw_interface_dump_t *mp;
    vl_api_sw_interface_details_t *rmp;
    uint32_t sw_if_index = ~0;

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_SW_INTERFACE_DUMP);
    mp->name_filter_valid = 1;
    strcpy(mp->name_filter, interface);
    if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        goto error;
    }
    if (!out_len)
    {
        goto error;
    }
    rmp = (void *)out;
    sw_if_index = ntohl(rmp->sw_if_index);

error:
    free(out);
    vl_msg_api_free(mp);
    return sw_if_index;
}

/**
 * (Un)-install a security policy database
 */
static status_t spd_add_del(bool add, uint32_t spd_id)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_spd_add_del_t *mp;
    vl_api_ipsec_spd_add_del_reply_t *rmp;
    status_t rv = FAILED;

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SPD_ADD_DEL);
    mp->is_add = add;
    mp->spd_id = ntohl(spd_id);
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    rv = SUCCESS;

error:
    free(out);
    vl_msg_api_free(mp);
    rv = SUCCESS;
    return rv;
}

/**
 * Enable or disable SPD on an insterface
 */
static status_t interface_add_del_spd(bool add, uint32_t spd_id, uint32_t sw_if_index)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_interface_add_del_spd_t *mp;
    vl_api_ipsec_interface_add_del_spd_reply_t *rmp;
    status_t rv = FAILED;

    if (g_interface){
            DBG1(DBG_KNL, " -- interface_add_del_spd g_interface return");
            return SUCCESS;
    }
    

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IPSEC_INTERFACE_ADD_DEL_SPD);
    mp->is_add = add;
    mp->spd_id = ntohl(spd_id);
    mp->sw_if_index = ntohl(sw_if_index);

    DBG1(DBG_KNL, "interface_add_del_spd add %u, spd_id %u, sw_if_index %u", add, spd_id, sw_if_index);
    DBG1(DBG_KNL, "interface_add_del_spd add %u, spd_id %u, sw_if_index %u", add, mp->spd_id, mp->sw_if_index);

    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s interface SPD failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s interface SPD failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    rv = SUCCESS;

error:
    free(out);
    vl_msg_api_free(mp);
    return rv;
}

#if 1

//#define clib_memcpy(d,s,n) memcpy(d,s,n)
//#define clib_memcpy_fast(d,s,n) memcpy(d,s,n)
typedef struct
{
  u8 is_add;
  u8 esn;
  u8 anti_replay;
  u32 local_ip, remote_ip;
  u32 local_spi;
  u32 remote_spi;
  u32 crypto_alg;
  u8 local_crypto_key_len;
  u8 local_crypto_key[128];
  u8 remote_crypto_key_len;
  u8 remote_crypto_key[128];
  u32 integ_alg;
  u8 local_integ_key_len;
  u8 local_integ_key[128];
  u8 remote_integ_key_len;
  u8 remote_integ_key[128];
  u8 renumber;
  u32 show_instance;
  u8 udp_encap;
  u32 tx_table_id;

//  ipsec_policy_t * policy;
  u32 spd_id;
} ipsec_add_del_tunnel_args_t;

#define exec_printf printf

void 
vpp_dump_hex(char *name, const u8 *buff, u32 len)
{
	int i=0;
	exec_printf("\n%12s : %u", name, len);

	for (i=0; i<len; i++){
		if (i%8 == 0)
			exec_printf("\n%12s : ", "");
		exec_printf("%02x ",buff[i]);
	}

	exec_printf("\n");
}

uint32_t g_ipsec_sw_if_index=0;
extern status_t vapi_interface_state_set(bool up, u32 sw_if_index);

static status_t ipsec_tunnel_if_add_del(bool add, ipsec_add_del_tunnel_args_t *a)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_tunnel_if_add_del_t *mp;
    vl_api_ipsec_tunnel_if_add_del_reply_t *rmp;
    status_t rv = FAILED;

//return 0;
    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IPSEC_TUNNEL_IF_ADD_DEL);
//
    DBG1(DBG_KNL, "enter ipsec_tunnel_if_add_del %s ", add ? "adding" : "removing");

    do {
        /*u32 local_spi = 0, remote_spi = 0;
        u32 crypto_alg = 0, integ_alg = 0;
        u8 lck[] = "lck00111222333444555666777888999", rck[] = "rck00111222333444555666777888999";
        u8 lik[] = "lik00111222333444555666777888999", rik[] = "rik00111222333444555666777888999";
        u32 local_ip = 0x11111111;
        u32 remote_ip = 0x11111112;
        u8 is_add = 1;
        u8 esn = 0;
        u8 anti_replay = 0;*/
        u8 renumber = 0;
        u32 instance = ~0;
        //int ret;
            
        mp->is_add = add;
        mp->esn = a->esn;
        mp->anti_replay = a->anti_replay;
        
        //mp->local_ip.data_u32 = local_ip;
        //mp->remote_ip.data_u32 = remote_ip;
        clib_memcpy (&mp->local_ip, &a->local_ip, sizeof (u32));
        clib_memcpy (&mp->remote_ip, &a->remote_ip, sizeof (u32));
        
        mp->local_spi = htonl (a->local_spi);
        mp->remote_spi = htonl (a->remote_spi);
        mp->crypto_alg = (u8) a->crypto_alg;
        
        mp->local_crypto_key_len = a->local_crypto_key_len;
        if (mp->local_crypto_key_len > sizeof (mp->local_crypto_key))
          mp->local_crypto_key_len = sizeof (mp->local_crypto_key);
        clib_memcpy (mp->local_crypto_key, a->local_crypto_key, mp->local_crypto_key_len);
        
        mp->remote_crypto_key_len = a->remote_crypto_key_len;
        if (mp->remote_crypto_key_len > sizeof (mp->remote_crypto_key))
          mp->remote_crypto_key_len = sizeof (mp->remote_crypto_key);
        clib_memcpy (mp->remote_crypto_key, a->remote_crypto_key, mp->remote_crypto_key_len);
        
        mp->integ_alg = (u8) a->integ_alg;
        
        mp->local_integ_key_len = a->local_integ_key_len;
        if (mp->local_integ_key_len > sizeof (mp->local_integ_key))
          mp->local_integ_key_len = sizeof (mp->local_integ_key);
        clib_memcpy (mp->local_integ_key, a->local_integ_key, mp->local_integ_key_len);

        
        mp->remote_integ_key_len = a->remote_integ_key_len;
        if (mp->remote_integ_key_len > sizeof (mp->remote_integ_key))
          mp->remote_integ_key_len = sizeof (mp->remote_integ_key);
        clib_memcpy (mp->remote_integ_key, a->remote_integ_key, mp->remote_integ_key_len);
        
        if (renumber)
          {
            mp->renumber = renumber;
            mp->show_instance = ntohl (instance);
          }
    }while(0);
//
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s interface SPD failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s interface SPD failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    g_ipsec_sw_if_index = ntohl(rmp->sw_if_index);
    DBG1(DBG_KNL, "add %d, g_ipsec_sw_if_index %u", add, g_ipsec_sw_if_index);
    rv = SUCCESS;

error:
    free(out);
    vl_msg_api_free(mp);
    return rv;
}

static status_t interface_route_add_del(/*private_kernel_vpp_net_t *this,*/ bool add,
                             u32 dst, uint8_t prefixlen, u32 sw_if_index, host_t *gtw)
{
    char *out;
    int out_len;
    //enumerator_t *enumerator;
   // iface_t *entry;
    vl_api_ip_add_del_route_t *mp;
    vl_api_ip_add_del_route_reply_t *rmp;
    //bool exists = FALSE;

    DBG1(DBG_KNL, "add %u, dst 0x%x, prefixlen %u, sw_if_index %u, ipsec_sw_if_index %u ", add,dst,prefixlen, sw_if_index, g_ipsec_sw_if_index);

    //if (!exists)
    //    return NOT_FOUND;

    mp = vl_msg_api_alloc(sizeof(*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IP_ADD_DEL_ROUTE);
    mp->is_add = add;
    mp->next_hop_sw_if_index = ntohl(g_ipsec_sw_if_index);//sw_if_index;
    mp->dst_address_length = prefixlen;
   memcpy(mp->dst_address, &dst, sizeof(dst));
    /*switch (dst.len)
    {
        case 4:
            mp->is_ipv6 = 0;
            memcpy(mp->dst_address, dst.ptr, dst.len);
            break;
        case 16:
            mp->is_ipv6 = 1;
            memcpy(mp->dst_address, dst.ptr, dst.len);
            break;
        default:
            vl_msg_api_free(mp);
            return FAILED;
    }*/
    if (gtw)
    {
        chunk_t addr = gtw->get_address(gtw);
        memcpy(mp->next_hop_address, addr.ptr, addr.len);
    }
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %sing route failed", add ? "add" : "remov");
        vl_msg_api_free(mp);
        return FAILED;
    }
    rmp = (void *)out;
    vl_msg_api_free(mp);
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s route failed %d", add ? "add" : "delete",
             ntohl(rmp->retval));
        free(out);
        return FAILED;
    }
    free(out);
    return SUCCESS;
}


status_t 
vapi_interface_set_unnumbered(u32 is_add, u32 sw_if_index)
{
    vl_api_sw_interface_set_unnumbered_t *mp;
    vl_api_sw_interface_set_unnumbered_reply_t *rmp;
    char *out;
    int out_len;
   // bool up=1;

    mp = vl_msg_api_alloc(sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_SW_INTERFACE_SET_UNNUMBERED);

        mp->is_add = is_add;

	mp->sw_if_index = ntohl(sw_if_index);
	mp->unnumbered_sw_if_index = ntohl(g_ipsec_sw_if_index);
        DBG1(DBG_KNL, "add %u, sw_if_index %u : %u", is_add, mp->unnumbered_sw_if_index, mp->sw_if_index);

    //vl_api_sw_interface_set_flags_t_endian(mp);

    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
            DBG1(DBG_KNL, "vac send failed");
        vl_msg_api_free(mp);
        return FAILED;
    }
    rmp = (void *)out;
    vl_msg_api_free(mp);
    if (rmp->retval)
    {
            DBG1(DBG_KNL, "%vac recv failed %d", ntohl(rmp->retval));
        free(out);
        return FAILED;
    }
    free(out);
    return SUCCESS;

}

void charon_socket_list_all()
{
        socket_manager_t *socket=charon->socket;

        DBG1(DBG_KNL, "%-28s : %u ", "get_port nat", socket->get_port(socket, 1));
        DBG1(DBG_KNL, "%-28s : %u ", "get_port", socket->get_port(socket, 0));
                
}

void charon_kernel_list_all()
{
        kernel_interface_t *kernel=charon->kernel;

        DBG1(DBG_KNL, "%-28s : %u ", "get_port nat", kernel->get_features(kernel));
        //DBG1(DBG_KNL, "%-28s : %u ", "get_port nat", kernel->get_interface(kernel));
        //DBG1(DBG_KNL, "%-28s : %u ", "get_port nat", kernel->create_address_enumerator(kernel));
        //DBG1(DBG_KNL, "%-28s : %u ", "get_port nat", kernel->create_local_subnet_enumerator(kernel));
                
}

void charon_controller_list_all()
{
	enumerator_t *enumerator;
	//enumerator_t *enum_task;
	//ike_cfg_t *ike_cfg;
	//child_cfg_t *child_cfg;
	child_sa_t *child_sa;
	ike_sa_t *ike_sa;
	//linked_list_t *my_ts, *other_ts;
	//bool first, found = FALSE;
        bool wait = TRUE;
        //task_t *task;
        //task_queue_t q;

         enumerator = charon->controller->create_ike_sa_enumerator(charon->controller, wait);
         while (enumerator->enumerate(enumerator, &ike_sa))
         {
         	enumerator_t *children = ike_sa->create_child_sa_enumerator(ike_sa);

//1. sa         
 		//log_ike_sa(out, ike_sa, all);
                printf("SA>>>, %H[%Y]...%H[%Y]\n",
                                ike_sa->get_my_host(ike_sa), ike_sa->get_my_id(ike_sa),
                                ike_sa->get_other_host(ike_sa), ike_sa->get_other_id(ike_sa));
// 2. child         
         	while (children->enumerate(children, (void**)&child_sa))
         	{
         			//log_child_sa(out, child_sa, all);
                                printf("CHILD>>>, %N%s SPIs: %.8x_i %.8x_o",
                                                protocol_id_names, child_sa->get_protocol(child_sa),
                                                child_sa->has_encap(child_sa) ? " in UDP" : "",
                                                ntohl(child_sa->get_spi(child_sa, TRUE)),
                                                ntohl(child_sa->get_spi(child_sa, FALSE)));
         	}
         	children->destroy(children);
// 3. task
/*                 {
                 
                         enum_task = ike_sa->create_task_enumerator(ike_sa, q);
                         while (enum_task->enumerate(enum_task, &task))
                         {
                                         printf("TASK>>>%12s[%d]: ", ike_sa->get_name(ike_sa),
                                                         ike_sa->get_unique_id(ike_sa));
                         }
                         enum_task->destroy(enum_task);
                 }*/


         }
         enumerator->destroy(enumerator);         
 }


void charon_ike_sa_manager_list_all()
{
        enumerator_t *sas;// *auths, *certs;
        ike_sa_t *ike_sa;
       // auth_cfg_t *auth;
      //  certificate_t *cert;
     //   auth_rule_t rule;

        sas = charon->ike_sa_manager->create_enumerator(charon->ike_sa_manager, TRUE);
        while (sas->enumerate(sas, &ike_sa))
        {
                printf("SA2>>>, %H[%Y]...%H[%Y]\n",
                                ike_sa->get_my_host(ike_sa), ike_sa->get_my_id(ike_sa),
                                ike_sa->get_other_host(ike_sa), ike_sa->get_other_id(ike_sa));
        }
        sas->destroy(sas);
}
void charon_child_sa_manager_list_all()
{
        //child_sa_manager_t *child_sa_manager=charon->child_sa_manager;

       // DBG1(DBG_KNL, "%-28s : %u ", "get_port nat", socket->get_port(socket, 1));
}
void charon_bus_list_all()
{
        //bus_t *bus=charon->bus;
	//void (*set_default_loggers)(daemon_t *this, level_t levels[DBG_MAX],bool to_stderr);
	//void (*set_level)(daemon_t *this, debug_t group, level_t level);

       // DBG1(DBG_KNL, "%-28s : %u ", "get_port nat", socket->get_port(socket, 1));
}

void sas_list_all(private_kernel_vpp_ipsec_t *this)
{
    enumerator_t *enumerator;
    //int out_len;
    //char *out;
    vl_api_ipsec_sad_entry_add_del_t *mp;
    sa_t *sa = NULL;

    DBG1(DBG_KNL, "%-10s 0x%-10s 0x%-10s 0x%-10s 0x%-10s ", "vl_msg_id", "sad_id", "spi", "src_addr", "dst_addr");
    this->mutex->lock(this->mutex);
    enumerator = this->sas->create_enumerator(this->sas);
    while (enumerator->enumerate(enumerator, &sa, NULL))
    {
        if (sa == NULL) continue;
        mp = sa->mp;
        mp->is_add = 0;
        DBG1(DBG_KNL, "%-10u 0x%-10u 0x%-10x 0x%-10x 0x%-10x ", 
                mp->_vl_msg_id, (mp->entry.sad_id), mp->entry.spi, mp->entry.tunnel_src, mp->entry.tunnel_dst);
    }
    enumerator->destroy(enumerator);
    this->mutex->unlock(this->mutex);

    return ;
}

void sas_show_all(private_kernel_vpp_ipsec_t *this)
{
    enumerator_t *enumerator;
   // int out_len;
   // char *out;
    vl_api_ipsec_sad_entry_add_del_t *mp;
    sa_t *sa = NULL;

    this->mutex->lock(this->mutex);
    enumerator = this->sas->create_enumerator(this->sas);
    while (enumerator->enumerate(enumerator, &sa, NULL))
    {
        if (sa == NULL) continue;
        DBG1(DBG_KNL, "*** sa ***");
        DBG1(DBG_KNL, "%-28s : %u ", "sa_id", sa->sa_id);

        mp = sa->mp;
        DBG1(DBG_KNL, "*** mp ***");
        DBG1(DBG_KNL, "%-28s : %u ", "_vl_msg_id", mp->_vl_msg_id);
        /*DBG1(DBG_KNL, "%-28s : %u ", "client_index", mp->client_index);
        DBG1(DBG_KNL, "%-28s : %u ", "context", mp->context);
        DBG1(DBG_KNL, "%-28s : %u ", "is_add", mp->is_add);
        DBG1(DBG_KNL, "%-28s : %u ", "sad_id", mp->sad_id);
        DBG1(DBG_KNL, "%-28s : 0x%x ", "spi", mp->spi);
        DBG1(DBG_KNL, "%-28s : %u ", "protocol", mp->protocol);

        DBG1(DBG_KNL, "%-28s : %u ", "crypto_algorithm", mp->crypto_algorithm);
        DBG1(DBG_KNL, "%-28s : %u ", "crypto_key_length", mp->crypto_key_length);
        vpp_dump_hex( "crypto_key_length", mp->crypto_key, mp->crypto_key_length);

        DBG1(DBG_KNL, "%-28s : %u ", "integrity_algorithm", mp->integrity_algorithm);
        DBG1(DBG_KNL, "%-28s : %u ", "integrity_key_length", mp->integrity_key_length);
        vpp_dump_hex( "integrity_key", mp->integrity_key, mp->integrity_key_length);

        DBG1(DBG_KNL, "%-28s : %u ", "use_extended_sequence_number", mp->use_extended_sequence_number);
        DBG1(DBG_KNL, "%-28s : %u ", "use_anti_replay", mp->use_anti_replay);
        DBG1(DBG_KNL, "%-28s : %u ", "is_tunnel", mp->is_tunnel);
        DBG1(DBG_KNL, "%-28s : %u ", "is_tunnel_ipv6", mp->is_tunnel_ipv6);
        DBG1(DBG_KNL, "%-28s : 0x%x ", "tunnel_src_address", mp->tunnel_src_address);
        DBG1(DBG_KNL, "%-28s : 0x%x ", "tunnel_dst_address", mp->tunnel_dst_address);
        DBG1(DBG_KNL, "%-28s : %u ", "udp_encap", mp->udp_encap);*/
    }
    enumerator->destroy(enumerator);
    this->mutex->unlock(this->mutex);

    return ;
}

static status_t manage_interface(private_kernel_vpp_ipsec_t *this, bool add,
                              kernel_ipsec_policy_id_t *id,
                              kernel_ipsec_manage_policy_t *data)
{
        uint32_t sw_if_index;
        sw_if_index = get_sw_if_index(id->interface);

                if (add == 0 && id->dir == POLICY_IN)
                {        
        //del route first
                        uint8_t mask;
                        host_t *net;
                        chunk_t src;
                        u32 tunnel_src_net;
                
                        id->src_ts->to_subnet(id->src_ts, &net, &mask);
                        
                        src = net->get_address(net);
                        memcpy(&tunnel_src_net, src.ptr, src.len);
                
                        DBG1(DBG_KNL, "call down src_ts, net %H, %u, tunnel_src_net 0x%x", net,mask, tunnel_src_net);
                        interface_route_add_del(FALSE, tunnel_src_net, 24, sw_if_index, NULL);
                }
        
        do{
                ipsec_add_del_tunnel_args_t a;
                memset (&a, 0, sizeof (a));
                 if (id->dir == POLICY_IN)
                 {                
                         vl_api_ipsec_sad_entry_add_del_t *other_mp;
                         vl_api_ipsec_sad_entry_t *other_ep;
                         kernel_ipsec_sa_id_t other_id = {
                             .src = data->dst,
                             .dst = data->src,
                             .proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
                             .spi = this->other_spi,
                         };
        
                         sa_t *other_sat = this->sas->get(this->sas, &other_id);
                         other_mp = other_sat->mp;
                         other_ep = &(other_mp->entry);
            
                    DBG1(DBG_KNL, "POLICY_IN111 add %d, sa_id %u", add, other_sat->sa_id);
                    DBG1(DBG_KNL, "spi 0x%x, this->my_spi 0x%x:0x%x ", data->sa->esp.spi, this->my_spi, this->other_spi);
                    DBG1(DBG_KNL, "other_mp->tunnel_src_address 0x%x:0x%x ", other_ep->tunnel_src, other_ep->tunnel_dst);
                    a.local_integ_key_len = other_ep->integrity_key.length;
                    clib_memcpy_fast (a.local_integ_key, other_ep->integrity_key.data, a.local_integ_key_len);
                    a.local_crypto_key_len = other_ep->crypto_key.length;
                    clib_memcpy_fast (a.local_crypto_key, other_ep->crypto_key.data, a.local_crypto_key_len);
                } 
                else{
                    DBG1(DBG_KNL, "POLICY_OUT %d ", add);
                }
        
                 if (id->dir == POLICY_IN)
                 {                
                         vl_api_ipsec_sad_entry_add_del_t *my_mp;
                         vl_api_ipsec_sad_entry_t *my_ep;
                         kernel_ipsec_sa_id_t my_id = {
                             .src = data->src,
                             .dst = data->dst,
                             .proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
                             .spi = this->my_spi,
                         };
                         sa_t *my_sat = this->sas->get(this->sas, &my_id);
                         my_mp = my_sat->mp;
                         my_ep = &(my_mp->entry);
            
                    DBG1(DBG_KNL, "POLICY_IN222 add %d, sa_id %u", add, my_sat->sa_id);
                    DBG1(DBG_KNL, "spi 0x%x, this->my_spi 0x%x:0x%x ", data->sa->esp.spi, this->my_spi, this->other_spi);
                    DBG1(DBG_KNL, "my_mp->tunnel_src_address 0x%x:0x%x ", my_ep->tunnel_src, my_ep->tunnel_dst);
                    a.is_add = add;
                    clib_memcpy (&a.local_ip, &my_ep->tunnel_dst, 4);
                    clib_memcpy (&a.remote_ip, &my_ep->tunnel_src, 4);
                    DBG1(DBG_KNL, "local_ip:remote_ip 0x%x:0x%x ", a.local_ip, a.remote_ip);
                    //proposals = child->i_proposals;
        
                    //a.local_spi = this->my_spi ;
                    //a.remote_spi = this->other_spi;
                    a.local_spi = ntohl(this->other_spi) ;
                    a.remote_spi = ntohl(this->my_spi);
                    
                    a.anti_replay = 1;
                    a.esn = 1;//my_mp->use_extended_sequence_number;
                    
                    a.integ_alg = my_ep->integrity_algorithm;
                    a.remote_integ_key_len = my_ep->integrity_key.length;
                    clib_memcpy_fast (a.remote_integ_key, my_ep->integrity_key.data, a.remote_integ_key_len);
                    
                    a.crypto_alg = my_ep->crypto_algorithm;
                    a.remote_crypto_key_len = my_ep->crypto_key.length;
                    clib_memcpy_fast (a.remote_crypto_key, my_ep->crypto_key.data, a.remote_crypto_key_len);
                } 
                else{
                    DBG1(DBG_KNL, "POLICY_OUT %d ", add);
                }
                
                if (id->dir == POLICY_IN)
                {        
                        u32 ipsec_index;
        
        //add
                        ipsec_tunnel_if_add_del(add, &a);
        //dump
                        ipsec_index = get_sw_if_index("ipsec0");
                        DBG1(DBG_KNL, "ipsec_index %u", ipsec_index);
        //route
                        do{
                                uint8_t mask;
                                host_t *net;
                                chunk_t src;
                                u32 tunnel_src_net;
                        
                                id->src_ts->to_subnet(id->src_ts, &net, &mask);
                                
                                src = net->get_address(net);
                                memcpy(&tunnel_src_net, src.ptr, src.len);
                        
                                DBG1(DBG_KNL, "src_ts, net %H, %u, tunnel_src_net 0x%x", net,mask, tunnel_src_net);
                                interface_route_add_del(add, tunnel_src_net, 24, sw_if_index, NULL);
                        }while(0);
                        do{
                                uint8_t mask;
                                host_t *net;
                                chunk_t dst;
                                u32 tunnel_dst_net;
                        
                                id->dst_ts->to_subnet(id->dst_ts, &net, &mask);
                                dst = net->get_address(net);
                                memcpy(&tunnel_dst_net, dst.ptr, dst.len);
                        
                                DBG1(DBG_KNL, "dst_ts, net %H, %u, tunnel_dst_net 0x%x", net, mask, tunnel_dst_net);
                                //interface_route_add_del(add, tunnel_dst_net, 24, sw_if_index, NULL);
                        }while(0);
                        DBG1(DBG_KNL, "set VPP interface sw_if_index %u", sw_if_index);
                        vapi_interface_state_set(TRUE, g_ipsec_sw_if_index);
                        vapi_interface_set_unnumbered(TRUE, sw_if_index);
                        
                }
                
        }while(0);


        return SUCCESS;

}

#endif

/**
 * Add or remove a bypass policy
 */
static status_t manage_bypass(bool add, uint32_t spd_id)
{
    vl_api_ipsec_spd_entry_add_del_t *mp;
    vl_api_ipsec_spd_entry_add_del_reply_t *rmp;
    char *out = NULL;
    int out_len;
    status_t rv = FAILED;
    uint16_t port;

    port = lib->settings->get_int(lib->settings, "%s.port", CHARON_UDP_PORT, lib->ns);

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));

    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SPD_ENTRY_ADD_DEL);
    mp->is_add = add;

    vl_api_ipsec_spd_entry_t *ep = &(mp->entry);
    ep->spd_id = ntohl(spd_id);
    ep->priority = ntohl(INT_MAX - POLICY_PRIORITY_PASS);
    ep->is_outbound = 0;
    ep->policy = ntohl(IPSEC_API_SPD_ACTION_BYPASS); // 0
    // ep->is_ip_any = 1;

    ep->local_address_start.af = ntohl(ADDRESS_IP4);
    ep->local_address_stop.af = ntohl(ADDRESS_IP4);
    ep->remote_address_start.af = ntohl(ADDRESS_IP4);
    ep->remote_address_stop.af = ntohl(ADDRESS_IP4);

    memset(&ep->local_address_stop.un.ip4, 0xFF, 16);
    memset(&ep->remote_address_stop.un.ip4, 0xFF, 16);
    ep->protocol = IPPROTO_ESP;
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    ep->is_outbound = 1;
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    ep->is_outbound = 0;
    ep->protocol = IPPROTO_AH;
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    ep->is_outbound = 1;
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    ep->is_outbound = 0;
    ep->protocol = IPPROTO_UDP;
    ep->local_port_start = ep->local_port_stop = ntohs(port);
    ep->remote_port_start = ep->remote_port_stop = ntohs(port);
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    ep->is_outbound = 1;
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    rv = SUCCESS;
error:
    free(out);
    vl_msg_api_free(mp);
    return rv;
}

/**
 * Add or remove a policy
 */
static status_t manage_policy(private_kernel_vpp_ipsec_t *this, bool add,
                              kernel_ipsec_policy_id_t *id,
                              kernel_ipsec_manage_policy_t *data)
{
    spd_t *spd;
    char *out = NULL, *interface;
    int out_len;
    uint32_t sw_if_index, spd_id, *sad_id;
    status_t rv = FAILED;
    uint32_t priority, auto_priority;
    chunk_t src_from, src_to, dst_from, dst_to;
    host_t *src, *dst, *addr;
    vl_api_ipsec_spd_entry_add_del_t *mp;
    vl_api_ipsec_spd_entry_add_del_reply_t *rmp;
    int is_ip6;

    mp = vl_msg_api_alloc (sizeof (*mp));
    memset(mp, 0, sizeof(*mp));

    this->mutex->lock(this->mutex);
    if (!id->interface)
    {
        addr = id->dir == POLICY_IN ? data->dst : data->src;
        DBG1(DBG_KNL, "addr %H", addr);
        DBG1(DBG_KNL, "data->dst %H", data->dst);
        DBG1(DBG_KNL, "data->src %H", data->src);
        
        if (!charon->kernel->get_interface(charon->kernel, addr, &interface))
        {
            DBG1(DBG_KNL, "policy no interface %H", addr);
            goto error;
        }
        id->interface = interface;
    }
    spd = this->spds->get(this->spds, id->interface);
    DBG1(DBG_KNL, "this->spds->get %u", spd);
    if (!spd)
    {
        if (!add)
        {
            DBG1(DBG_KNL, "SPD for %s not found", id->interface);
            goto error;
        }
        sw_if_index = get_sw_if_index(id->interface);
        if (sw_if_index == ~0)
        {
            DBG1(DBG_KNL, "sw_if_index for %s not found", id->interface);
            goto error;
        }
        spd_id = ref_get(&this->next_spd_id);
        if (spd_add_del(TRUE, spd_id))
        {
            goto error;
        }
        if (manage_bypass(TRUE, spd_id))
        {
            goto error;
        }
        if (interface_add_del_spd(TRUE, spd_id, sw_if_index))
        {
            goto error;
        }
        INIT(spd,
                .spd_id = spd_id,
                .sw_if_index = sw_if_index,
                .policy_num = 0,
        );
        this->spds->put(this->spds, id->interface, spd);
    }
    DBG1(DBG_KNL, "this->spds->get after %u", spd);

    auto_priority = calculate_priority(data->prio, id->src_ts, id->dst_ts);
    priority = data->manual_prio ? data->manual_prio : auto_priority;

    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SPD_ENTRY_ADD_DEL);
    mp->is_add = add;

    vl_api_ipsec_spd_entry_t *ep = &(mp->entry);
    ep->spd_id = ntohl(spd->spd_id);
    ep->priority = ntohl(INT_MAX - priority);
    ep->is_outbound = id->dir == POLICY_OUT;
    switch (data->type)
    {
        case POLICY_IPSEC:
            ep->policy = ntohl(IPSEC_API_SPD_ACTION_PROTECT); // 3
            break;
        case POLICY_PASS:
            ep->policy = ntohl(IPSEC_API_SPD_ACTION_BYPASS); // 0
            break;
        case POLICY_DROP:
            ep->policy = ntohl(IPSEC_API_SPD_ACTION_DISCARD);//  1
            break;
    }
    ep->policy = htonl(ep->policy);
    if ((data->type == POLICY_IPSEC) && data->sa)
    {
        kernel_ipsec_sa_id_t id = {
                .src = data->src,
                .dst = data->dst,
                .proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
                .spi = data->sa->esp.use ? data->sa->esp.spi : data->sa->ah.spi,
        };
        sad_id = this->sas->get(this->sas, &id);
        if (!sad_id)
        {
            DBG1(DBG_KNL, "SA ID not found");
            goto error;
        }
        ep->sa_id = ntohl(*sad_id);
    }

    is_ip6 = (id->src_ts->get_type(id->src_ts) == TS_IPV6_ADDR_RANGE);
    //ep->is_ipv6 = id->src_ts->get_type(id->src_ts) == TS_IPV6_ADDR_RANGE;
    ep->protocol = id->src_ts->get_protocol(id->src_ts);

    if (id->dir == POLICY_OUT)
    {
        src_from = id->src_ts->get_from_address(id->src_ts);
        src_to = id->src_ts->get_to_address(id->src_ts);
        src = host_create_from_chunk(AF_INET, src_to, 0);
        dst_from = id->dst_ts->get_from_address(id->dst_ts);
        dst_to = id->dst_ts->get_to_address(id->dst_ts);
        dst = host_create_from_chunk(AF_INET, dst_to, 0);
    }
    else
    {
        dst_from = id->src_ts->get_from_address(id->src_ts);
        dst_to = id->src_ts->get_to_address(id->src_ts);
        dst = host_create_from_chunk(AF_INET, src_to, 0);
        src_from = id->dst_ts->get_from_address(id->dst_ts);
        src_to = id->dst_ts->get_to_address(id->dst_ts);
        src = host_create_from_chunk(AF_INET, dst_to, 0);
    }

    if (src->is_anyaddr(src) && dst->is_anyaddr(dst))
    {
        // mp->is_ip_any = 1;
    }
    else
    {
    
    ep->local_address_start.af = ntohl(ADDRESS_IP4);
    ep->local_address_stop.af = ntohl(ADDRESS_IP4);
    ep->remote_address_start.af = ntohl(ADDRESS_IP4);
    ep->remote_address_stop.af = ntohl(ADDRESS_IP4);
    
        memcpy(&ep->local_address_start.un.ip4, src_from.ptr, src_from.len);
        memcpy(&ep->local_address_stop.un.ip4, src_to.ptr, src_to.len);
        memcpy(&ep->remote_address_start.un.ip4, dst_from.ptr, dst_from.len);
        memcpy(&ep->remote_address_stop.un.ip4, dst_to.ptr, dst_to.len);
    }
    ep->local_port_start = ntohs(id->src_ts->get_from_port(id->src_ts));
    ep->local_port_stop = ntohs(id->src_ts->get_to_port(id->src_ts));
    ep->remote_port_start = ntohs(id->dst_ts->get_from_port(id->dst_ts));
    ep->remote_port_stop = ntohs(id->dst_ts->get_to_port(id->dst_ts));

    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac %s SPD entry failed", add ? "adding" : "removing");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "%s SPD entry failed rv:%d", add ? "add" : "remove", ntohl(rmp->retval));
        goto error;
    }
    if (add)
    {
        ref_get(&spd->policy_num);
    }
    else
    {
        if (ref_put(&spd->policy_num))
        {
            interface_add_del_spd(FALSE, spd->spd_id, spd->sw_if_index);
            manage_bypass(FALSE, spd->spd_id);
            spd_add_del(FALSE, spd->spd_id);
            this->spds->remove(this->spds, id->interface);
        }
    }
    if (this->install_routes && id->dir == POLICY_OUT && !ep->protocol)
    {
        if (data->type == POLICY_IPSEC && data->sa->mode != MODE_TRANSPORT)
        {
            manage_route(this, add, id->dst_ts, data->src, data->dst);
        }
    }
    if (g_interface) {
        manage_interface(this, add, id, data);
    }
#if 0
        if (add == 0 && id->dir == POLICY_IN)
        {        
//del route first
                uint8_t mask;
                host_t *net;
                chunk_t src;
                u32 tunnel_src_net;
        
                id->src_ts->to_subnet(id->src_ts, &net, &mask);
                
                src = net->get_address(net);
                memcpy(&tunnel_src_net, src.ptr, src.len);
        
                DBG1(DBG_KNL, "call down src_ts, net %H, %u, tunnel_src_net 0x%x", net,mask, tunnel_src_net);
                interface_route_add_del(FALSE, tunnel_src_net, 24, sw_if_index, NULL);
        }

do{
        ipsec_add_del_tunnel_args_t a;
        memset (&a, 0, sizeof (a));
         if (id->dir == POLICY_IN)
         {                
                 vl_api_ipsec_sad_add_del_entry_t *other_mp;
                 kernel_ipsec_sa_id_t other_id = {
                     .src = data->dst,
                     .dst = data->src,
                     .proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
                     .spi = this->other_spi,
                 };

                 sa_t *other_sat = this->sas->get(this->sas, &other_id);
                 other_mp = other_sat->mp;
    
            DBG1(DBG_KNL, "POLICY_IN111 add %d, sa_id %u", add, other_sat->sa_id);
            DBG1(DBG_KNL, "spi 0x%x, this->my_spi 0x%x:0x%x ", data->sa->esp.spi, this->my_spi, this->other_spi);
            DBG1(DBG_KNL, "other_mp->tunnel_src_address 0x%x:0x%x ", other_mp->tunnel_src_address, other_mp->tunnel_dst_address);
            a.local_integ_key_len = other_mp->integrity_key_length;
            clib_memcpy_fast (a.local_integ_key, other_mp->integrity_key, a.local_integ_key_len);
            a.local_crypto_key_len = other_mp->crypto_key_length;
            clib_memcpy_fast (a.local_crypto_key, other_mp->crypto_key, a.local_crypto_key_len);
        } 
        else{
            DBG1(DBG_KNL, "POLICY_OUT %d ", add);
        }

         if (id->dir == POLICY_IN)
         {                
                 vl_api_ipsec_sad_add_del_entry_t *my_mp;
                 kernel_ipsec_sa_id_t my_id = {
                     .src = data->src,
                     .dst = data->dst,
                     .proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
                     .spi = this->my_spi,
                 };
                 sa_t *my_sat = this->sas->get(this->sas, &my_id);
                 my_mp = my_sat->mp;
    
            DBG1(DBG_KNL, "POLICY_IN222 add %d, sa_id %u", add, my_sat->sa_id);
            DBG1(DBG_KNL, "spi 0x%x, this->my_spi 0x%x:0x%x ", data->sa->esp.spi, this->my_spi, this->other_spi);
            DBG1(DBG_KNL, "my_mp->tunnel_src_address 0x%x:0x%x ", my_mp->tunnel_src_address, my_mp->tunnel_dst_address);
            a.is_add = add;
            clib_memcpy (&a.local_ip, my_mp->tunnel_dst_address, 4);
            clib_memcpy (&a.remote_ip, my_mp->tunnel_src_address, 4);
            DBG1(DBG_KNL, "local_ip:remote_ip 0x%x:0x%x ", a.local_ip, a.remote_ip);
            //proposals = child->i_proposals;

            //a.local_spi = this->my_spi ;
            //a.remote_spi = this->other_spi;
            a.local_spi = ntohl(this->other_spi) ;
            a.remote_spi = ntohl(this->my_spi);
            
            a.anti_replay = 1;
            a.esn = my_mp->use_extended_sequence_number;
            
            a.integ_alg = my_mp->integrity_algorithm;
            a.remote_integ_key_len = my_mp->integrity_key_length;
            clib_memcpy_fast (a.remote_integ_key, my_mp->integrity_key, a.remote_integ_key_len);
            
            a.crypto_alg = my_mp->crypto_algorithm;
            a.remote_crypto_key_len = my_mp->crypto_key_length;
            clib_memcpy_fast (a.remote_crypto_key, my_mp->crypto_key, a.remote_crypto_key_len);
        } 
        else{
            DBG1(DBG_KNL, "POLICY_OUT %d ", add);
        }
        
        if (id->dir == POLICY_IN)
        {        
                u32 ipsec_index;

//add
                ipsec_tunnel_if_add_del(add, &a);
//dump
                ipsec_index = get_sw_if_index("ipsec0");
                DBG1(DBG_KNL, "ipsec_index %u", ipsec_index);
//route
                do{
                        uint8_t mask;
                        host_t *net;
                        chunk_t src;
                        u32 tunnel_src_net;
                
                        id->src_ts->to_subnet(id->src_ts, &net, &mask);
                        
                        src = net->get_address(net);
                        memcpy(&tunnel_src_net, src.ptr, src.len);
                
                        DBG1(DBG_KNL, "src_ts, net %H, %u, tunnel_src_net 0x%x", net,mask, tunnel_src_net);
                        interface_route_add_del(add, tunnel_src_net, 24, sw_if_index, NULL);
                }while(0);
                do{
                        uint8_t mask;
                        host_t *net;
                        chunk_t dst;
                        u32 tunnel_dst_net;
                
                        id->dst_ts->to_subnet(id->dst_ts, &net, &mask);
                        dst = net->get_address(net);
                        memcpy(&tunnel_dst_net, dst.ptr, dst.len);
                
                        DBG1(DBG_KNL, "dst_ts, net %H, %u, tunnel_dst_net 0x%x", net, mask, tunnel_dst_net);
                        //interface_route_add_del(add, tunnel_dst_net, 24, sw_if_index, NULL);
                }while(0);
                DBG1(DBG_KNL, "set VPP interface sw_if_index %u", sw_if_index);
                vapi_interface_state_set(TRUE, g_ipsec_sw_if_index);
                vapi_interface_set_unnumbered(TRUE, sw_if_index);
                
        }
        
}while(0);
#endif    
    
    rv = SUCCESS;
error:
    free(out);
    vl_msg_api_free(mp);
    this->mutex->unlock(this->mutex);
    return rv;
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
    private_kernel_vpp_ipsec_t *this)
{
    return KERNEL_ESP_V3_TFC;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
    private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
    uint8_t protocol, uint32_t *spi)
{
    static const u_int p = 268435399, offset = 0xc0000000;

    *spi = htonl(offset + permute(ref_get(&this->nextspi) ^ this->mixspi, p));
    return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
    private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
    uint16_t *cpi)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_add_sa_t *data)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_sad_entry_add_del_t *mp;
    vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
    uint32_t sad_id = ref_get(&this->next_sad_id);
    uint8_t ca = 0, ia = 0;
    status_t rv = FAILED;
    chunk_t src, dst;
    kernel_ipsec_sa_id_t *sa_id;
    sa_t *sa;
    vl_api_ipsec_sad_flags_t flags = IPSEC_API_SAD_FLAG_NONE;

//
    this->initiator = data->initiator;
    if (data->inbound){
        this->up_time = time_monotonic(NULL);
        this->my_spi = id->spi;
    }
    else
        this->other_spi = id->spi;
    DBG1(DBG_KNL, "data->initiator %u, inbound %u, spi 0x%x!",data->initiator, data->inbound, id->spi);
//    
    mp = vl_msg_api_alloc(sizeof(*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SAD_ENTRY_ADD_DEL);
    mp->is_add = 1;

    vl_api_ipsec_sad_entry_t *ep = &(mp->entry);
    ep->sad_id = ntohl(sad_id);
    ep->spi = id->spi;
    ep->protocol = id->proto == IPPROTO_ESP;
    ep->protocol = ntohl(ep->protocol);
    switch (data->enc_alg)
    {
        case ENCR_NULL:
            ca = IPSEC_API_CRYPTO_ALG_NONE;
            break;
        case ENCR_AES_CBC:
            switch (data->enc_key.len * 8)
            {
                case 128:
                    ca = IPSEC_API_CRYPTO_ALG_AES_CBC_128;
                    break;
                case 192:
                    ca = IPSEC_API_CRYPTO_ALG_AES_CBC_192;
                    break;
                case 256:
                    ca = IPSEC_API_CRYPTO_ALG_AES_CBC_192;
                    break;
                default:
                    goto error;
                    break;
            }
            break;
        case ENCR_3DES:
            ca = IPSEC_API_CRYPTO_ALG_3DES_CBC;
            break;
        default:
            DBG1(DBG_KNL, "algorithm %N not supported by VPP!",
                 encryption_algorithm_names, data->enc_alg);
            goto error;
            break;
    }
    ep->crypto_algorithm = ntohl(ca);
    ep->crypto_key.length = data->enc_key.len;
    memcpy(ep->crypto_key.data, data->enc_key.ptr, data->enc_key.len);

#if 0//reference
#define foreach_ipsec_integ_alg                                            \
      _ (0, NONE, "none")                                                      \
      _ (1, MD5_96, "md5-96")           /* RFC2403 */                          \
      _ (2, SHA1_96, "sha1-96")         /* RFC2404 */                          \
      _ (3, SHA_256_96, "sha-256-96")   /* draft-ietf-ipsec-ciph-sha-256-00 */ \
      _(4, SHA_224_112, "sha-224-112") /* RFC 3874 */                                                                                               \
      _(5, SHA_256_128, "sha-256-128") /* RFC4868 */                          \
      _(6, SHA_384_192, "sha-384-192") /* RFC4868 */                          \
      _(7, SHA_512_256, "sha-512-256")      /* RFC4868 */                                                                                                   \
      _(8, AES_XCBC, "aes-xcbc")                            /* RFC3566 */                                                                                                   \
      _(9, AES_CMAC, "aes-cmac")    /* pdcp */ \
      _(10, ZUC_EIA3, "zuc-eia3")   /* pdcp */ \
      _(11, SNOW3G_UIA2, "snow3g-uia2")     /* pdcp */ \
      _(12, PDCP_NULL, "pdcp-null") /* pdcp */
#endif
    switch (data->int_alg)
    {
        case AUTH_UNDEFINED:
            ia = 200U;  // not defined
            break;
        case AUTH_HMAC_MD5_96:
            ia = IPSEC_API_INTEG_ALG_MD5_96;
            break;
        case AUTH_HMAC_SHA1_96:
            ia = IPSEC_API_INTEG_ALG_SHA1_96;
            break;
        case AUTH_HMAC_SHA2_256_128:
            ia = IPSEC_API_INTEG_ALG_SHA_256_128;
            break;
        case AUTH_HMAC_SHA2_384_192:
            ia = IPSEC_API_INTEG_ALG_SHA_384_192;
            break;
        case AUTH_HMAC_SHA2_512_256:
            ia = IPSEC_API_INTEG_ALG_SHA_512_256;
            break;
        default:
            DBG1(DBG_KNL, "algorithm %N not supported by VPP!",
                 integrity_algorithm_names, data->int_alg);
            goto error;
            break;
    }
    ep->integrity_algorithm = ntohl(ia);
    ep->integrity_key.length = data->int_key.len;
    memcpy(ep->integrity_key.data, data->int_key.ptr, data->int_key.len);

//    mp->use_extended_sequence_number = data->esn;
    if (data->esn)
            flags |= IPSEC_API_SAD_FLAG_USE_EXTENDED_SEQ_NUM;

    DBG1(DBG_KNL, "esn 0x%x:%u", flags, data->esn);

    if (data->mode == MODE_TUNNEL)
    {
        flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
        //mp->is_tunnel = 1;
        //mp->is_tunnel_ipv6 = id->src->get_family(id->src) == AF_INET6;
    }

    DBG1(DBG_KNL, "MODE_TUNNEL 0x%x:%u", flags, data->mode);

//    ep->udp_encap = data->encap;
    if (data->encap)
            flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;

    DBG1(DBG_KNL, "udp_encap 0x%x:%u", flags, data->encap);

    ep->flags = ntohl(flags);

    src = id->src->get_address(id->src);
    ep->tunnel_src.af = ntohl(ADDRESS_IP4);
    memcpy(&ep->tunnel_src.un.ip4, src.ptr, src.len);
    
    dst = id->dst->get_address(id->dst);
    ep->tunnel_dst.af = ntohl(ADDRESS_IP4);
    memcpy(&ep->tunnel_dst.un.ip4, dst.ptr, dst.len);

    /*if (g_interface){
            DBG1(DBG_KNL, "-- add SA g_interface return");
            return SUCCESS;

    }*/
    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac adding SA failed");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "add SA failed rv:%d", ntohl(rmp->retval));
        goto error;
    }

    this->mutex->lock(this->mutex);
    INIT(sa_id,
            .src = id->src->clone(id->src),
            .dst = id->dst->clone(id->dst),
            .spi = id->spi,
            .proto = id->proto,
    );
    INIT(sa,
            .sa_id = sad_id,
            .mp = mp,
    );
    this->sas->put(this->sas, sa_id, sa);
    this->mutex->unlock(this->mutex);
    rv = SUCCESS;

error:
    free(out);
    return rv;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_update_sa_t *data)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
    time_t *time)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_sa_dump_t *mp;
    vl_api_ipsec_sa_details_t *rmp;
    status_t rv = FAILED;
    sa_t *sa;

    
    sas_show_all(this);
    sas_list_all(this);
    charon_socket_list_all();
    charon_controller_list_all();
    charon_ike_sa_manager_list_all();

    this->mutex->lock(this->mutex);
    sa = this->sas->get(this->sas, id);
    this->mutex->unlock(this->mutex);
    if (!sa)
    {
        DBG1(DBG_KNL, "SA not found");
        return NOT_FOUND;
    }
    mp = vl_msg_api_alloc(sizeof(*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_IPSEC_SA_DUMP);
    mp->sa_id = ntohl(sa->sa_id);
    if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac SA dump failed");
        goto error;
    }
    if (!out_len)
    {
        DBG1(DBG_KNL, "SA ID %d no data", sa->sa_id);
        rv = NOT_FOUND;
        goto error;
    }
    rmp = (void*)out;

    if (bytes)
    {
        *bytes = htonll(rmp->total_data_size);
    }
    if (packets)
    {
        //*packets = 0;
        *packets = htonll(rmp->total_packet);
    }
    DBG1(DBG_KNL, "SA ID %d packets %u, bytes %u", sa->sa_id, *packets, *bytes);
    if (time)
    {
        *time = this->up_time;
    }
    rv = SUCCESS;
error:
    free(out);
    vl_msg_api_free(mp);
    return rv;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
    kernel_ipsec_del_sa_t *data)
{
    char *out = NULL;
    int out_len;
    vl_api_ipsec_sad_entry_add_del_t *mp;
    vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
    status_t rv = FAILED;
    sa_t *sa;

    this->mutex->lock(this->mutex);
    sa = this->sas->get(this->sas, id);
    if (!sa)
    {
        DBG1(DBG_KNL, "SA not found");
        rv = NOT_FOUND;
        goto error;
    }
    mp = sa->mp;
    mp->is_add = 0;

    if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
    {
        DBG1(DBG_KNL, "vac removing SA failed");
        goto error;
    }
    rmp = (void *)out;
    if (rmp->retval)
    {
        DBG1(DBG_KNL, "del SA failed rv:%d", ntohl(rmp->retval));
        goto error;
    }

    vl_msg_api_free(mp);
    this->sas->remove(this->sas, id);
    rv = SUCCESS;
error:
    free(out);
    this->mutex->unlock(this->mutex);
    return rv;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
    private_kernel_vpp_ipsec_t *this)
{
    enumerator_t *enumerator;
    int out_len;
    char *out;
    vl_api_ipsec_sad_entry_add_del_t *mp;
    sa_t *sa = NULL;

    this->mutex->lock(this->mutex);
    enumerator = this->sas->create_enumerator(this->sas);
    while (enumerator->enumerate(enumerator, sa, NULL))
    {
        mp = sa->mp;
        mp->is_add = 0;
        if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
        {
            break;
        }
        free(out);
        vl_msg_api_free(mp);
        this->sas->remove_at(this->sas, enumerator);
    }
    enumerator->destroy(enumerator);
    this->mutex->unlock(this->mutex);

    return SUCCESS;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_manage_policy_t *data)
{
    return manage_policy(this, TRUE, id, data);
}

METHOD(kernel_ipsec_t, query_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_query_policy_t *data, time_t *use_time)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
    private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
    kernel_ipsec_manage_policy_t *data)
{
    return manage_policy(this, FALSE, id, data);
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
    private_kernel_vpp_ipsec_t *this)
{
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
    private_kernel_vpp_ipsec_t *this, int fd, int family)
{
    return FALSE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
    private_kernel_vpp_ipsec_t *this, int fd, int family, u_int16_t port)
{
    return FALSE;
}

METHOD(kernel_ipsec_t, destroy, void,
    private_kernel_vpp_ipsec_t *this)
{
    this->mutex->destroy(this->mutex);
    this->sas->destroy(this->sas);
    this->spds->destroy(this->spds);
    this->routes->destroy(this->routes);
    free(this);
}

kernel_vpp_ipsec_t *kernel_vpp_ipsec_create()
{
    private_kernel_vpp_ipsec_t *this;

    INIT(this,
        .public = {
            .interface = {
                .get_features = _get_features,
                .get_spi = _get_spi,
                .get_cpi = _get_cpi,
                .add_sa  = _add_sa,
                .update_sa = _update_sa,
                .query_sa = _query_sa,
                .del_sa = _del_sa,
                .flush_sas = _flush_sas,
                .add_policy = _add_policy,
                .query_policy = _query_policy,
                .del_policy = _del_policy,
                .flush_policies = _flush_policies,
                .bypass_socket = _bypass_socket,
                .enable_udp_decap = _enable_udp_decap,
                .destroy = _destroy,
            },
        },
        .next_sad_id = 0,
        .next_spd_id = 0,
        .mutex = mutex_create(MUTEX_TYPE_DEFAULT),
        .sas = hashtable_create((hashtable_hash_t)sa_hash,
                                (hashtable_equals_t)sa_equals, 32),
        .spds = hashtable_create((hashtable_hash_t)interface_hash,
                                 (hashtable_equals_t)interface_equals, 4),
        .routes = linked_list_create(),
        .install_routes = lib->settings->get_bool(lib->settings,
                            "%s.install_routes", TRUE, lib->ns),
        .vpp_interface=lib->settings->get_bool(lib->settings,
                            "%s.vpp_interface", VPP_INTERFACE_FEATURE, lib->ns),
    );

    if (!init_spi(this))
    {
        destroy(this);
        return NULL;
    }
    g_interface = lib->settings->get_bool(lib->settings,
                        "%s.vpp_interface", VPP_INTERFACE_FEATURE, lib->ns),
    DBG1(DBG_KNL, "get config vpp_interface:%d", g_interface);
    
    return &this->public;
}
