/*
 *------------------------------------------------------------------
 * vxlan_api.c - vxlan api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

/*
 *  Copyright (C) 2020 flexiWAN Ltd.
 *  List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *   - enable enforcement of interface, where VXLAN tunnel should send unicast
 *     packets from. This is need for the FlexiWAN Multi-link feature.
 *   - Add destination port for vxlan tunnle, if remote device is behind NAT. Port is
 *     provisioned by fleximanage when creating the tunnel.
 *
 *  - acl_based_classification: Feature to provide traffic classification using
 *  ACL plugin. Matching ACLs provide the service class and importance
 *  attribute. The classification result is marked in the packet and can be
 *  made use of in other functions like scheduling, policing, marking etc.
 *
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/vxlan/vxlan.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#ifdef FLEXIWAN_FEATURE
#include <vnet/udp/udp_local.h>
#endif

#define foreach_vpe_api_msg                             \
_(SW_INTERFACE_SET_VXLAN_BYPASS, sw_interface_set_vxlan_bypass)         \
_(VXLAN_ADD_DEL_TUNNEL, vxlan_add_del_tunnel)                           \
_(VXLAN_TUNNEL_DUMP, vxlan_tunnel_dump)                                 \
_(VXLAN_OFFLOAD_RX, vxlan_offload_rx)

static void
vl_api_vxlan_offload_rx_t_handler (vl_api_vxlan_offload_rx_t * mp)
{
  vl_api_vxlan_offload_rx_reply_t *rmp;
  int rv = 0;
  u32 hw_if_index = ntohl (mp->hw_if_index);
  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (!vnet_hw_interface_is_valid (vnet_get_main (), hw_if_index))
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto err;
    }
  VALIDATE_SW_IF_INDEX (mp);

  u32 t_index = vnet_vxlan_get_tunnel_index (sw_if_index);
  if (t_index == ~0)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX_2;
      goto err;
    }

  vxlan_main_t *vxm = &vxlan_main;
  vxlan_tunnel_t *t = pool_elt_at_index (vxm->tunnels, t_index);
  if (!ip46_address_is_ip4 (&t->dst))
    {
      rv = VNET_API_ERROR_INVALID_ADDRESS_FAMILY;
      goto err;
    }

  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw_if = vnet_get_hw_interface (vnm, hw_if_index);
  ip4_main_t *im = &ip4_main;
  u32 rx_fib_index =
    vec_elt (im->fib_index_by_sw_if_index, hw_if->sw_if_index);

  if (t->encap_fib_index != rx_fib_index)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto err;
    }

  if (vnet_vxlan_add_del_rx_flow (hw_if_index, t_index, mp->enable))
    {
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto err;
    }
  BAD_SW_IF_INDEX_LABEL;
err:

  REPLY_MACRO (VL_API_VXLAN_OFFLOAD_RX_REPLY);
}

static void
  vl_api_sw_interface_set_vxlan_bypass_t_handler
  (vl_api_sw_interface_set_vxlan_bypass_t * mp)
{
  vl_api_sw_interface_set_vxlan_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  vnet_int_vxlan_bypass_mode (sw_if_index, mp->is_ipv6, mp->enable);
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_VXLAN_BYPASS_REPLY);
}

static void vl_api_vxlan_add_del_tunnel_t_handler
  (vl_api_vxlan_add_del_tunnel_t * mp)
{
  vl_api_vxlan_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  bool is_ipv6;
  u32 fib_index;
  ip46_address_t src, dst;
#ifdef FLEXIWAN_FEATURE
  ip46_address_t next_hop_ip;
#endif /* FLEXIWAN_FEATURE */

  ip_address_decode (&mp->src_address, &src);
  ip_address_decode (&mp->dst_address, &dst);
#ifdef FLEXIWAN_FEATURE
  ip_address_decode (&mp->next_hop_ip, &next_hop_ip);
#endif /* FLEXIWAN_FEATURE */

  if (ip46_address_is_ip4 (&src) != ip46_address_is_ip4 (&dst))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  is_ipv6 = !ip46_address_is_ip4 (&src);

  fib_index = fib_table_find (fib_ip_proto (is_ipv6),
			      ntohl (mp->encap_vrf_id));
  if (fib_index == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  vnet_vxlan_add_del_tunnel_args_t a = {
    .is_add = mp->is_add,
    .is_ip6 = is_ipv6,
    .instance = ntohl (mp->instance),
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .encap_fib_index = fib_index,
    .decap_next_index = ntohl (mp->decap_next_index),
    .vni = ntohl (mp->vni),
    .dst = dst,
    .src = src,
#ifdef FLEXIWAN_FEATURE
    .next_hop.frp_proto = is_ipv6 ? DPO_PROTO_IP6 : DPO_PROTO_IP4,
    .next_hop.frp_sw_if_index = ntohl (mp->next_hop_sw_if_index),
    .next_hop.frp_addr = next_hop_ip,
#endif /* FLEXIWAN_FEATURE */
#ifdef FLEXIWAN_FEATURE
    .dest_port = clib_net_to_host_u16 (mp->dest_port),
#endif

#ifdef FLEXIWAN_FEATURE  /* acl_based_classification */
    .qos_id = clib_net_to_host_u32 (mp->qos_id),
#endif  /* FLEXIWAN_FEATURE - acl_based_classification */
  };

#ifdef FLEXIWAN_FEATURE
  /* set default port if none is provided */
  if (a.dest_port == 0)
    a.dest_port = vxlan_main.vxlan_port;
#endif
  /* Check src & dst are different */
  if (ip46_address_cmp (&a.dst, &a.src) == 0)
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  if (ip46_address_is_multicast (&a.dst) &&
      !vnet_sw_if_index_is_api_valid (a.mcast_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
    }

  u32 sw_if_index = ~0;
  rv = vnet_vxlan_add_del_tunnel (&a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_VXLAN_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_vxlan_tunnel_details
  (vxlan_tunnel_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_vxlan_tunnel_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_VXLAN_TUNNEL_DETAILS);

  ip_address_encode (&t->src, IP46_TYPE_ANY, &rmp->src_address);
  ip_address_encode (&t->dst, IP46_TYPE_ANY, &rmp->dst_address);

  if (ip46_address_is_ip4 (&t->dst))
    rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].ft_table_id);
  else
    rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].ft_table_id);

  rmp->instance = htonl (t->user_instance);
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->vni = htonl (t->vni);
  rmp->decap_next_index = htonl (t->decap_next_index);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;
#ifdef FLEXIWAN_FEATURE
  rmp->dest_port = clib_host_to_net_u16(t->dest_port);
#endif

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_vxlan_tunnel_dump_t_handler
  (vl_api_vxlan_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  vxlan_main_t *vxm = &vxlan_main;
  vxlan_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, vxm->tunnels)
       {
        send_vxlan_tunnel_details(t, reg, mp->context);
      }
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (vxm->tunnel_index_by_sw_if_index)) ||
	  (~0 == vxm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &vxm->tunnels[vxm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_vxlan_tunnel_details (t, reg, mp->context);
    }
}

/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_vxlan;
#undef _
}

static clib_error_t *
vxlan_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  am->api_trace_cfg[VL_API_VXLAN_ADD_DEL_TUNNEL].size += 16 * sizeof (u32);

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (vxlan_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
