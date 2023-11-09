/*
 * Copyright 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *  Copyright (C) 2019 flexiWAN Ltd.
 *  List of fixes made for FlexiWAN (denoted by FLEXIWAN_FIX flag):
 *   - enable VxLan decapsulation before packets are pushed into TAP
 *   - hide internally used loopback interfaces from TAP/Linux
 *
 *  List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *   - nat-tap-inject-output: Support to NAT packets received from tap
 *     interface before being put on wire
 *   - show tap-inject [name|tap|sw_if_index]: dump tap-inject info for specific interface
 *   - handle no-vppsb flag added in the VPP to enable VPPSB to ignore interfaces
 *   - don't route all ARP traffic directly to VPPSB. Instead, register VPPSB tap-neighbor
 *     node within "arp" arc, enabling thus ARP traffic to pass the VRRP module
 *     before reaching the VPPSB.
 */

#include "tap_inject.h"
#include <librtnl/netns.h>
#include <linux/if_ether.h>
#include <netlink/route/link/vlan.h>

#include <vnet/mfib/mfib_table.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/lookup.h>
#include <vnet/fib/fib.h>
#include <vnet/osi/osi.h>
#include <vnet/gre/gre.h>

#ifdef FLEXIWAN_FIX
#include <vlib/log.h>
#include <vnet/udp/udp.h>
#include <plugins/vrrp/vrrp.h>
#include <dlfcn.h>
#endif

static tap_inject_main_t tap_inject_main;
extern dpo_type_t tap_inject_dpo_type;
extern vlib_node_registration_t tap_inject_pppoe_tx_node;

static clib_error_t *
tap_inject_vlan_add (struct vnet_main_t * vnet_main, u32 sw_if_index);

static clib_error_t *
tap_inject_vlan_del (u32 sw_if_index);

tap_inject_main_t *
tap_inject_get_main (void)
{
  return &tap_inject_main;
}

void
#ifdef FLEXIWAN_FEATURE
tap_inject_insert_tap (u32 sw_if_index, u32 tap_fd, u32 tap_if_index, u8* tap_if_name)
#else
tap_inject_insert_tap (u32 sw_if_index, u32 tap_fd, u32 tap_if_index)
#endif /* FLEXIWAN_FEATURE */
{
  tap_inject_main_t * im = tap_inject_get_main ();

  if (tap_inject_debug_is_enabled())
    {
      clib_warning("sw_if_index: %d, tap_fd: %d, tap_if_index: %d, tap_if_name: %v",
                   sw_if_index, tap_fd, tap_if_index, tap_if_name);
    }

  vec_validate_init_empty (im->sw_if_index_to_tap_fd, sw_if_index, ~0);
  vec_validate_init_empty (im->sw_if_index_to_tap_if_index, sw_if_index, ~0);
#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
  vec_validate_init_empty (im->sw_if_index_to_ip4_output, sw_if_index, 0);
  vec_validate_init_empty (im->sw_if_index_to_tap_name, sw_if_index, 0);
  im->sw_if_index_to_tap_name[sw_if_index] = tap_if_name;
  if (!im->tap_if_index_by_name)
    im->tap_if_index_by_name = hash_create_string ( /* size */ 0, sizeof (uword));
  hash_set_mem (im->tap_if_index_by_name, tap_if_name, tap_if_index);
#endif /* FLEXIWAN_FEATURE */

  if (tap_fd != ~0)
    {
      vec_validate_init_empty (im->tap_fd_to_sw_if_index, tap_fd, ~0);
      im->sw_if_index_to_tap_fd[sw_if_index] = tap_fd;
      im->tap_fd_to_sw_if_index[tap_fd] = sw_if_index;
    }

  vec_validate_init_empty (im->sw_if_index_to_sw_if_index, sw_if_index, ~0);
  im->sw_if_index_to_tap_if_index[sw_if_index] = tap_if_index;

  hash_set (im->tap_if_index_to_sw_if_index, tap_if_index, sw_if_index);
  vec_validate_init_empty (im->type, sw_if_index, 0);
}

void tap_inject_map_tap_if_index_to_sw_if_index (u32 tap_if_index, u32 sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  hash_set (im->tap_if_index_to_sw_if_index, tap_if_index, sw_if_index);

  vec_validate_init_empty (im->sw_if_index_to_tap_if_index, sw_if_index, ~0);
  im->sw_if_index_to_tap_if_index[sw_if_index] = tap_if_index;
}

void tap_inject_unmap_tap_if_index_to_sw_if_index (u32 tap_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  hash_unset (im->tap_if_index_to_sw_if_index, tap_if_index);
}

void tap_inject_map_interface_set (u32 src_sw_if_index, u32 dst_sw_if_index)
{
  tap_inject_main_t *im = tap_inject_get_main();

  vec_validate_init_empty (im->sw_if_index_to_sw_if_index, src_sw_if_index, ~0);
  im->sw_if_index_to_sw_if_index[src_sw_if_index] =  dst_sw_if_index;

  vec_validate_init_empty (im->sw_if_index_to_tap_fd, dst_sw_if_index, ~0);
  im->sw_if_index_to_tap_fd[dst_sw_if_index] = im->sw_if_index_to_tap_fd[src_sw_if_index];

  tap_inject_type_set(dst_sw_if_index, TAP_INJECT_MAPPED);
}

void tap_inject_map_interface_delete (u32 src_sw_if_index, u32 dst_sw_if_index)
{
  tap_inject_main_t *im = tap_inject_get_main();

  im->sw_if_index_to_tap_fd[dst_sw_if_index] = ~0;

  im->sw_if_index_to_sw_if_index[src_sw_if_index] = ~0;
}

u32 tap_inject_map_interface_get (u32 sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  u32 new_sw_if_index = ~0;

  vec_validate_init_empty (im->sw_if_index_to_sw_if_index, sw_if_index, ~0);
  new_sw_if_index = im->sw_if_index_to_sw_if_index[sw_if_index];

  return new_sw_if_index;
}

void tap_inject_vlan_sw_if_index_add_del (u16 vlan, u32 parent_sw_if_index, u32 vlan_sw_if_index, u32 add)
{
  tap_inject_main_t *im = tap_inject_get_main();
  tap_inject_vlan_key_t key;

  key.k = 0;
  key.key.vlan = vlan;
  key.key.parent_sw_if_index = parent_sw_if_index;

  if (add)
    {
      hash_set (im->vlan_to_sw_if_index, key.k, vlan_sw_if_index);
      hash_set (im->sw_if_index_to_vlan, vlan_sw_if_index, key.k);
    }
  else
    {
      hash_unset (im->vlan_to_sw_if_index, key.k);
      hash_unset (im->sw_if_index_to_vlan, vlan_sw_if_index);
    }
}

u32 tap_inject_vlan_sw_if_index_get (u16 vlan, u32 parent_sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  uword *p = 0;
  u32 sw_if_index = ~0;
  tap_inject_vlan_key_t key;

  key.k = 0;
  key.key.vlan = vlan;
  key.key.parent_sw_if_index = parent_sw_if_index;

  p = hash_get (im->vlan_to_sw_if_index, key.k);
  if (p)
    sw_if_index = p[0];

  return sw_if_index;
}

int tap_inject_sw_if_index_vlan_get (u32 vlan_sw_if_index, u16 *vlan, u32 *parent_sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  uword *p = 0;
  tap_inject_vlan_key_t key;

  p = hash_get (im->sw_if_index_to_vlan, vlan_sw_if_index);
  if (p) {
    key.k = p[0];
    *vlan = key.key.vlan;
    *parent_sw_if_index = key.key.parent_sw_if_index;
    return 0;
  }

  return -1;
}

void
tap_inject_delete_tap (u32 sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  if (tap_inject_debug_is_enabled())
    {
      clib_warning("sw_if_index: %d", sw_if_index);
    }

  if (im->type[sw_if_index] == 0)
    {
      return;
    }

  u32 tap_fd = im->sw_if_index_to_tap_fd[sw_if_index];
  u32 tap_if_index = im->sw_if_index_to_tap_if_index[sw_if_index];
#ifdef FLEXIWAN_FEATURE
  u8 * tap_if_name = im->sw_if_index_to_tap_name[sw_if_index];
#endif /* FLEXIWAN_FEATURE */

  im->sw_if_index_to_tap_if_index[sw_if_index] = ~0;
  im->sw_if_index_to_tap_fd[sw_if_index] = ~0;
#ifdef FLEXIWAN_FEATURE
  im->sw_if_index_to_ip4_output[sw_if_index] = 0;

  if (tap_if_name != NULL)
    {
      hash_unset_mem (im->tap_if_index_by_name, tap_if_name);
      im->sw_if_index_to_tap_name[sw_if_index] = NULL;
      vec_free(tap_if_name);
    }
#endif /* FLEXIWAN_FEATURE */

  if (tap_fd != ~0 && !tap_inject_type_check(sw_if_index, TAP_INJECT_MAPPED)) {
    im->tap_fd_to_sw_if_index[tap_fd] = ~0;
  }
  im->sw_if_index_to_sw_if_index[sw_if_index] = ~0;
  im->type[sw_if_index] = 0;

  hash_unset (im->tap_if_index_to_sw_if_index, tap_if_index);
}

u32
tap_inject_lookup_tap_fd (u32 sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  vec_validate_init_empty (im->sw_if_index_to_tap_fd, sw_if_index, ~0);
  return im->sw_if_index_to_tap_fd[sw_if_index];
}

u32
tap_inject_lookup_sw_if_index_from_tap_fd (u32 tap_fd)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  vec_validate_init_empty (im->tap_fd_to_sw_if_index, tap_fd, ~0);
  return im->tap_fd_to_sw_if_index[tap_fd];
}

u32
tap_inject_lookup_sw_if_index_from_tap_if_index (u32 tap_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  uword * sw_if_index;

  sw_if_index = hash_get (im->tap_if_index_to_sw_if_index, tap_if_index);
  return sw_if_index ? *(u32 *)sw_if_index : ~0;
}

#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
u32
tap_inject_is_enabled_ip4_output (u32 sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  vec_validate_init_empty (im->sw_if_index_to_ip4_output, sw_if_index, 0);
  return im->sw_if_index_to_ip4_output[sw_if_index];
}

void
tap_inject_enable_ip4_output (u32 sw_if_index, u32 enable)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  vec_validate_init_empty (im->sw_if_index_to_ip4_output, sw_if_index, 0);
  im->sw_if_index_to_ip4_output[sw_if_index] = enable;
}

#endif /* FLEXIWAN_FEATURE */


void vrrp_add_del_vr_ip_ip4(int is_add, ip4_address_t* a)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  if (is_add)
    vec_add1(im->vrrp_vr_ip4s, a->as_u32);
  else
  {
    u32 index = vec_search (im->vrrp_vr_ip4s, a->as_u32);
    if (index != ~0)
      vec_del1(im->vrrp_vr_ip4s, index);
  }
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    // .version = VPP_BUILD_VER, FIXME
    .description = "router",
};
/* *INDENT-ON* */


static void
tap_inject_disable (void)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  im->flags &= ~TAP_INJECT_F_ENABLED;

  clib_warning ("tap-inject is not actually disabled.");
}

static clib_error_t *
tap_inject_enable (void)
{
  vlib_main_t * vm = vlib_get_main ();
  tap_inject_main_t * im = tap_inject_get_main ();

  if (log_main.default_syslog_log_level > VLIB_LOG_LEVEL_NOTICE)
  {
      im->flags |= TAP_INJECT_F_DEBUG_ENABLE;
      rtnl_enable_debug(1);
  }

  if (tap_inject_is_enabled ())
    return 0;

  tap_inject_enable_netlink ();

#ifdef FLEXIWAN_FIX
  {
    void (*func_vrrp_set_cb_vr_ip_add_del)(vrrp_add_del_vr_ip_ip4_cb, vrrp_add_del_vr_ip_ip6_cb);
    func_vrrp_set_cb_vr_ip_add_del = vlib_get_plugin_symbol ("vrrp_plugin.so", "vrrp_set_cb_vr_ip_add_del");
    if (!func_vrrp_set_cb_vr_ip_add_del)
    {
        return clib_error_return (0, "vlib_get_plugin_symbol(vrrp_plugin.so, vrrp_set_cb_vr_ip_add_del) failed");
    }
    func_vrrp_set_cb_vr_ip_add_del(vrrp_add_del_vr_ip_ip4, NULL);
  }
#endif /* FLEXIWAN_FIX */

  /* Only enable netlink? */
  if (im->flags & TAP_INJECT_F_CONFIG_NETLINK)
    {
      im->flags |= TAP_INJECT_F_ENABLED;
      return 0;
    }

  /* Register ARP and ICMP6 as neighbor nodes. */
#ifndef FLEXIWAN_FIX
  ethernet_register_input_type (vm, ETHERNET_TYPE_ARP, im->neighbor_node_index);
#endif /* FLEXIWAN_FIX */
  ip6_register_protocol (IP_PROTOCOL_ICMP6, im->neighbor_node_index);

  /* Register remaining protocols. */
  ip4_register_protocol (IP_PROTOCOL_ICMP, im->tx_node_index);

  ip4_register_protocol (IP_PROTOCOL_OSPF, im->tx_node_index);
  ip4_register_protocol (IP_PROTOCOL_TCP, im->tx_node_index);

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_SESSION,
                                tap_inject_pppoe_tx_node.index);

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_DISCOVERY,
                                tap_inject_pppoe_tx_node.index);
#ifdef FLEXIWAN_FIX
  // Issue: all UDP traffic is captured by tap-inject before VxLan node intercepts it.
  //        as a result VxLAN tunnel that sits on BVI bridge with TAP interface does not work.
  // Solution: comment out tap-inject registration on UDP traffic. This allows traffic to reach
  //           VxLAN node. UDP traffic designated for TAP will reach udp-local node and will be dropped.
  //           To avoid drop and to pass it to tap-inject, the punt feature is used.
  //           Punt arc is used to redirect traffic that was supposed to be dropped into various nodes
  //           that are registered Punt feature. Registration is performed by adding tap-inject into
  //           ip4-punt arc.
  udp_punt_unknown(vm, 1, 1);
  vnet_feature_enable_disable ("ip4-punt", "tap-inject-tx", 0, 1, 0, 0);
#else
  ip4_register_protocol (IP_PROTOCOL_UDP, im->tx_node_index);
#endif /* FLEXIWAN_FIX */

  ip6_register_protocol (IP_PROTOCOL_OSPF, im->tx_node_index);
  ip6_register_protocol (IP_PROTOCOL_TCP, im->tx_node_index);
#ifdef FLEXIWAN_FIX
  udp_punt_unknown(vm, 0, 1);
  vnet_feature_enable_disable ("ip6-punt", "ip6-tap-inject-tx", 0, 1, 0, 0);
#else
  ip6_register_protocol (IP_PROTOCOL_UDP, im->tx_node_index);
#endif /* FLEXIWAN_FIX */
  /* Registering ISIS to OSI node. */
  osi_register_input_protocol (OSI_PROTOCOL_isis, im->tx_node_index);

  {
    dpo_id_t dpo = DPO_INVALID;

    const mfib_prefix_t pfx_224_0_0_0 = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xe0000000),
        },
        .fp_src_addr = {
            .ip4.as_u32 = 0,
        },
    };

    dpo_set(&dpo, tap_inject_dpo_type, DPO_PROTO_IP4, ~0);

    index_t repi = replicate_create(1, DPO_PROTO_IP4);
    replicate_set_bucket(repi, 0, &dpo);

    mfib_table_entry_special_add(0,
                                 &pfx_224_0_0_0,
                                 MFIB_SOURCE_API,
                                 MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF,
                                 repi);

    dpo_reset(&dpo);
  }

  im->flags |= TAP_INJECT_F_ENABLED;

  return 0;
}

static uword
tap_inject_iface_isr (vlib_main_t * vm, vlib_node_runtime_t * node,
                      vlib_frame_t * f)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  vnet_main_t * vnet_main = vnet_get_main ();
  vnet_sw_interface_t * sw;
  vnet_hw_interface_t * hw;
  u32 * sw_if_index;
  clib_error_t * err = 0;
  uword is_sub;

  vec_foreach (sw_if_index, im->interfaces_to_enable)
    {
      sw = vnet_get_sw_interface (vnet_main, *sw_if_index);
      is_sub = vnet_sw_interface_is_sub (vnet_main, sw->sw_if_index);
      if (is_sub)
        {
          tap_inject_vlan_add(vnet_main, *sw_if_index);
          continue;
        }

      hw = vnet_get_hw_interface (vnet_main, sw->hw_if_index);

      if (hw->hw_class_index == ethernet_hw_interface_class.index ||
          hw->hw_class_index == tun_device_hw_interface_class.index)
        {
#ifdef FLEXIWAN_FIX
          if (hw->dev_class_index == gre_device_class.index)
            {
              continue;
            }
#endif /* FLEXIWAN_FIX */

          err = tap_inject_tap_connect (hw);
          if (err) {
            clib_error("%v", err->what);
            break;
          }
        }
    }

  vec_foreach (sw_if_index, im->interfaces_to_disable)
    {
      if (tap_inject_type_check(*sw_if_index, TAP_INJECT_VLAN))
        tap_inject_vlan_del(*sw_if_index);
      else
        tap_inject_tap_disconnect (*sw_if_index);
    }

  vec_free (im->interfaces_to_enable);
  vec_free (im->interfaces_to_disable);

  return err ? -1 : 0;
}

VLIB_REGISTER_NODE (tap_inject_iface_isr_node, static) = {
  .function = tap_inject_iface_isr,
  .name = "tap-inject-iface-isr",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};


static clib_error_t *
tap_inject_interface_add_del (struct vnet_main_t * vnet_main, u32 sw_if_index,
                              u32 add)
{
  vlib_main_t * vm = vlib_get_main ();
  tap_inject_main_t * im = tap_inject_get_main ();

  if (!tap_inject_is_config_enabled ())
    return 0;

  tap_inject_enable ();

#ifdef FLEXIWAN_FIX
  vnet_feature_enable_disable ("arp", "tap-inject-neighbor", sw_if_index, add, 0, 0);
#endif /* FLEXIWAN_FIX */

#ifdef FLEXIWAN_FIX
  // As of Dec-2019 we use loop0-bridge-l2gre_ipsec_tunnel and loop1-bridge-vxlan_tunnel
  // in order to enable NAT 1:1. The loop1 interface should not be exposed to Linux/user,
  // as it is for internal use only, and no ping/netplan etc should be enabled.
  // Therefore we hide it from user by escaping it in this function.
  vnet_sw_interface_t * sw = vnet_get_sw_interface (vnet_main, sw_if_index);
  if (vnet_hw_interface_get_flexiwan_flag(vnet_main, sw->hw_if_index, VNET_INTERFACE_FLEXIWAN_FLAG_NO_VPPSB))
    {
      return 0;
    }
#endif /* FLEXIWAN_FIX */

  if (add)
    vec_add1 (im->interfaces_to_enable, sw_if_index);
  else
    vec_add1 (im->interfaces_to_disable, sw_if_index);

  vlib_node_set_interrupt_pending (vm, tap_inject_iface_isr_node.index);

  return 0;
}

static clib_error_t *
tap_inject_netlink_add_link_vlan (int parent, u32 vlan, u16 proto, u8 *name, int *if_index)
{
  struct rtnl_link *link;
  struct nl_sock *sk;
  int err;

  if (tap_inject_debug_is_enabled())
  {
    clib_warning("parent %u, vlan %u, proto %u, name %s",
                 parent, vlan, proto, name);
  }

  sk = nl_socket_alloc ();
  if ((err = nl_connect (sk, NETLINK_ROUTE)) < 0)
    {
      clib_error("connect error: %d", err);
      nl_socket_free (sk);
      return clib_error_return (NULL, "Unable to connect socket: %d", err);
    }

  link = rtnl_link_vlan_alloc ();

  rtnl_link_set_link (link, parent);
  rtnl_link_set_name (link, (const char*)name);
  rtnl_link_vlan_set_id (link, vlan);
  rtnl_link_vlan_set_protocol (link, htons (proto));

  if ((err = rtnl_link_add (sk, link, NLM_F_CREATE)) < 0)
    {
      clib_error("link add error: %d", err);
      rtnl_link_put (link);
      nl_socket_free (sk);
      return clib_error_return (NULL, "Unable to add link %s: %d", name, err);
    }

  *if_index = if_nametoindex((const char*)name);

  if (tap_inject_debug_is_enabled())
  {
    clib_warning("vlan was created, if_index %u", *if_index);
  }

  rtnl_link_put (link);
  nl_socket_free (sk);

  return NULL;
}

static clib_error_t *
tap_inject_netlink_del_link (u8 *name)
{
  struct rtnl_link *link;
  struct nl_sock *sk;
  int err;

  sk = nl_socket_alloc ();
  if ((err = nl_connect (sk, NETLINK_ROUTE)) < 0)
    {
      clib_error("Unable to connect socket: %s", strerror(errno));
      nl_socket_free (sk);
      return clib_error_return (NULL, "Unable to connect socket: %s", strerror(errno));
    }

  link = rtnl_link_alloc ();
  rtnl_link_set_name (link, (const char*)name);

  if ((err = rtnl_link_delete (sk, link)) < 0)
    {
      clib_error("Unable to del link %s: %s", name, strerror(errno));
      rtnl_link_put (link);
      nl_socket_free (sk);
      return clib_error_return (NULL, "Unable to del link %s: %s", name, strerror(errno));
    }

  rtnl_link_put (link);
  nl_socket_free (sk);

  return NULL;
}

static clib_error_t *
tap_inject_vlan_add (struct vnet_main_t * vnet_main, u32 sw_if_index)
{
  const vnet_sw_interface_t *sw;
  u16 outer_vlan;
  u16 outer_proto;
  u32 parent_sw_if_index;
  u32 parent_if_index;
  clib_error_t *err;
  u8* parent_name;
  u8* name;
  int if_index = ~0;
  u32 type;
  tap_inject_main_t * im = tap_inject_get_main ();

  sw = vnet_get_sw_interface_or_null (vnet_main, sw_if_index);
  if (!sw)
    {
      return clib_error_return (NULL, "Can not find sw_if_index %u", sw_if_index);
    }

  if (sw->sub.eth.flags.dot1ad)
    {
      return clib_error_return (NULL, "8021AD is not supported");
    }

  parent_sw_if_index = sw->sup_sw_if_index;
  parent_if_index = im->sw_if_index_to_tap_if_index[parent_sw_if_index];
  parent_name = im->sw_if_index_to_tap_name[parent_sw_if_index];
  outer_vlan = sw->sub.eth.outer_vlan_id;
  outer_proto = ETH_P_8021Q;

  name = format (0, "%s.%u", parent_name, outer_vlan);

  err = tap_inject_netlink_add_link_vlan (parent_if_index, outer_vlan, outer_proto,
					                                name, &if_index);
  if (err)
    return err;

  tap_inject_insert_tap(sw_if_index, ~0, if_index, name);
  tap_inject_map_interface_set(parent_sw_if_index, sw_if_index);
  type = tap_inject_type_get(parent_sw_if_index);
  tap_inject_type_set(sw_if_index, type | TAP_INJECT_VLAN | outer_vlan << 16);
  tap_inject_vlan_sw_if_index_add_del(outer_vlan, parent_sw_if_index, sw_if_index, 1);

  return NULL;
}

static clib_error_t *
tap_inject_vlan_del (u32 sw_if_index)
{
  int ret = 0;
  clib_error_t * err = 0;
  u16 vlan = 0;
  u32 parent_sw_if_index = 0;
  u8* name;
  tap_inject_main_t * im = tap_inject_get_main ();

  name = im->sw_if_index_to_tap_name[sw_if_index];

  err = tap_inject_netlink_del_link(name);
  if (err) {
    clib_error("%v", err->what);
    return err;
  }

  ret = tap_inject_sw_if_index_vlan_get(sw_if_index, &vlan, &parent_sw_if_index);
  if (ret < 0) {
    clib_error("VLAN with sw_if_index %u not found", sw_if_index);
    return NULL;
  }

  tap_inject_vlan_sw_if_index_add_del(vlan, parent_sw_if_index, sw_if_index, 0);

  tap_inject_delete_tap(sw_if_index);

  return NULL;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (tap_inject_interface_add_del);

static clib_error_t *
tap_inject_enable_disable_all_interfaces (int enable)
{
  vnet_main_t * vnet_main = vnet_get_main ();
  tap_inject_main_t * im = tap_inject_get_main ();
  vnet_sw_interface_t * interfaces;
  vnet_sw_interface_t * sw;
  u32 ** indices;
  u32 * sw_if_index;

  if (enable)
    tap_inject_enable ();
  else
    tap_inject_disable ();

  /* Collect all the interface indices. */
  interfaces = vnet_main->interface_main.sw_interfaces;
  indices = enable ? &im->interfaces_to_enable : &im->interfaces_to_disable;
  pool_foreach (sw, interfaces) {vec_add1 (*indices, sw - interfaces);};

#ifdef FLEXIWAN_FIX
  vec_foreach (sw_if_index, *indices) {
    if (enable)
        vnet_feature_enable_disable ("arp", "tap-inject-neighbor", *sw_if_index, 1, 0, 0);
    else
        vnet_feature_enable_disable ("arp", "tap-inject-neighbor", *sw_if_index, 0, 0, 0);
  };
#endif /* FLEXIWAN_FIX */

  if (tap_inject_iface_isr (vlib_get_main (), 0, 0))
    return clib_error_return (0, "tap-inject interface add del isr failed");

  return 0;
}

static clib_error_t *
tap_inject_cli (vlib_main_t * vm, unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  if (cmd->function_arg)
    {
      clib_error_t * err;

      if (tap_inject_is_config_disabled ())
        return clib_error_return (0,
            "tap-inject is disabled in config, thus cannot be enabled.");

      /* Enable */
      err = tap_inject_enable_disable_all_interfaces (1);
      if (err)
        {
          tap_inject_enable_disable_all_interfaces (0);
          return err;
        }

      im->flags |= TAP_INJECT_F_CONFIG_ENABLE;
    }
  else
    {
      /* Disable */
      tap_inject_enable_disable_all_interfaces (0);
      im->flags &= ~TAP_INJECT_F_CONFIG_ENABLE;
    }

  return 0;
}

VLIB_CLI_COMMAND (tap_inject_enable_cmd, static) = {
  .path = "enable tap-inject",
  .short_help = "enable tap-inject",
  .function = tap_inject_cli,
  .function_arg = 1,
};

VLIB_CLI_COMMAND (tap_inject_disable_cmd, static) = {
  .path = "disable tap-inject",
  .short_help = "disable tap-inject",
  .function = tap_inject_cli,
  .function_arg = 0,
};

static clib_error_t *
tap_inject_debug_cli (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  if (cmd->function_arg)
    {
      /* Enable */
      im->flags |= TAP_INJECT_F_DEBUG_ENABLE;
    }
  else
    {
      /* Disable */
      im->flags &= ~TAP_INJECT_F_DEBUG_ENABLE;
    }

    rtnl_enable_debug(cmd->function_arg);

  return 0;
}

VLIB_CLI_COMMAND (tap_inject_enable_debug_cmd, static) = {
  .path = "enable tap-inject debug",
  .short_help = "enable tap-inject debug",
  .function = tap_inject_debug_cli,
  .function_arg = 1,
};

VLIB_CLI_COMMAND (tap_inject_disable_debug_cmd, static) = {
  .path = "disable tap-inject debug",
  .short_help = "disable tap-inject debug",
  .function = tap_inject_debug_cli,
  .function_arg = 0,
};


#ifdef FLEXIWAN_FEATURE
/* We hash tap names to provide quick fetch of vpp interface name to tap name map. 
   This hash might become out of sync with real names in Linux, if user change
   interface names in shell, e.g. using set-name directive of netplan.
   The tap_inject_validate_hashes() function validates consistency of the hashes
   and update them if needed.
*/
static void tap_inject_validate_hashes ()
{
  tap_inject_main_t * im = tap_inject_get_main ();

  typedef struct _stale_tap
  {
    u32 sw_if_index;
    u32 tap_if_index;
    u8* tap_name;
    u8* linux_name;
  } stale_tap;

  stale_tap   tap, *pstale;
  stale_tap * stale_taps = 0;


  hash_foreach (tap.tap_if_index, tap.sw_if_index, im->tap_if_index_to_sw_if_index, {

      tap.linux_name = format(0, "%U", format_tap_inject_tap_name, tap.tap_if_index);
      tap.tap_name   = im->sw_if_index_to_tap_name[tap.sw_if_index];

      if (tap.linux_name != 0 && tap.sw_if_index < vec_len(im->sw_if_index_to_tap_name) &&
          tap.tap_name != 0  &&  strcmp((char*)tap.tap_name, (char*)tap.linux_name) != 0)
        {
            vec_add1(stale_taps, tap);
        }
      else
        {
            vec_free(tap.linux_name);
        }
    });

  vec_foreach(pstale, stale_taps) {
      clib_warning("tap_inject_validate_hashes: sw_if_index=%d/tap_if_index=%d:  %s -> %s",
          pstale->sw_if_index, pstale->tap_if_index, pstale->tap_name, pstale->linux_name);

      im->sw_if_index_to_tap_name[pstale->sw_if_index] = pstale->linux_name;
      hash_unset_mem (im->tap_if_index_by_name, pstale->tap_name);
      hash_set_mem (im->tap_if_index_by_name, pstale->linux_name, pstale->tap_if_index);
      vec_free(pstale->tap_name);
  }

  vec_free(stale_taps);
}
#endif /*#ifdef FLEXIWAN_FEATURE*/

static clib_error_t *
show_tap_inject (vlib_main_t * vm, unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  vnet_main_t * vnet_main = vnet_get_main ();
  tap_inject_main_t * im = tap_inject_get_main ();
  u32 k, v;
#ifdef FLEXIWAN_FIX
  u32     sw_if_index = INDEX_INVALID;
  u32     tap_if_index = INDEX_INVALID;
  u8    * tap_if_name = 0;
  uword * p_tap_if_index;
  uword * p_sw_if_index;
#endif /*#ifdef FLEXIWAN_FIX*/

  if (tap_inject_is_config_disabled ())
    {
      vlib_cli_output (vm, "tap-inject is disabled in config.\n");
      return 0;
    }

  if (!tap_inject_is_enabled ())
    {
      vlib_cli_output (vm, "tap-inject is not enabled.\n");
      return 0;
    }

#ifdef FLEXIWAN_FEATURE

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sw_if_index %d", &sw_if_index))
        ;
      else if (unformat (input, "tap_name %s", &tap_if_name))
        ;
      else if (unformat (input, "%U",
                         unformat_vnet_sw_interface, vnet_main, &sw_if_index))
        ;
      else
        return (clib_error_return (0, "unknown input '%U'",
				                           format_unformat_error, input));
    }

  if (sw_if_index != INDEX_INVALID)
    {
        if (PREDICT_FALSE(vec_len(im->sw_if_index_to_tap_if_index) <= sw_if_index))
            return (clib_error_return (0, "sw_if_index %d not found", sw_if_index));
        tap_if_index = im->sw_if_index_to_tap_if_index[sw_if_index];
        if (PREDICT_FALSE(tap_if_index == INDEX_INVALID))
            return (clib_error_return (0, "no tap was found for sw_if_index %d", sw_if_index));
        vlib_cli_output (vm, "%U -> %U",
                format_vnet_sw_interface_name, vnet_main,
                vnet_get_sw_interface (vnet_main, sw_if_index),
                format_tap_inject_tap_name, tap_if_index);
        return 0;
    }
  else if (tap_if_name)
    {
      p_tap_if_index = hash_get_mem (im->tap_if_index_by_name, tap_if_name);
      if (PREDICT_FALSE(p_tap_if_index == 0))
        {
          /*there is a chance the tap_if_name in hash does not match the real
            name in Linux. That might happen if name that was set by vppsb
			on tap creation, was changed by user from witin Linux, e.g. using
			the netplan set-name directive.
            To handle this case we just go and ensure/update all hashes.
          */
          tap_inject_validate_hashes();

          /* if still no luck, return error.
          */
          p_tap_if_index = hash_get_mem (im->tap_if_index_by_name, tap_if_name);
          if (PREDICT_FALSE(p_tap_if_index == 0))
            return (clib_error_return (0, "no tap was found for tap_if_name=%s", tap_if_name));
        }

      tap_if_index = p_tap_if_index[0];

      p_sw_if_index = hash_get (im->tap_if_index_to_sw_if_index, tap_if_index);
      if (PREDICT_FALSE(p_sw_if_index == 0))
        return (clib_error_return (0, "no sw_if_index was found for tap_if_name=%s(%d)",
            tap_if_name, tap_if_index));
      sw_if_index = p_sw_if_index[0];

      vlib_cli_output (vm, "%U -> %s",
              format_vnet_sw_interface_name, vnet_main,
              vnet_get_sw_interface (vnet_main, sw_if_index), tap_if_name);
      return 0;
    }
#endif /*#ifdef FLEXIWAN_FEATURE*/

  hash_foreach (k, v, im->tap_if_index_to_sw_if_index, {
    vlib_cli_output (vm, "%U -> %U",
            format_vnet_sw_interface_name, vnet_main,
            vnet_get_sw_interface (vnet_main, v),
            format_tap_inject_tap_name, k);
  });

  return 0;
}

VLIB_CLI_COMMAND (show_tap_inject_cmd, static) = {
  .path = "show tap-inject",
  .short_help = "show tap-inject [<if name> | sw_if_index <sw_if_index> | tap_name <name in linux>]",
  .function = show_tap_inject,
};


#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
static clib_error_t *
tap_inject_enable_ip4_output_cli (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  i32 is_del = 0;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main(), &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "Invalid sw_if_index");
      goto done;
    }
  if (tap_inject_lookup_tap_fd(sw_if_index) == ~0)
    {
      error = clib_error_return (0, "The input is not a tap interface ");
      goto done;
    }
  if (is_del)
    {
      tap_inject_enable_ip4_output (sw_if_index, 0);
    }
  else
    {
      if (im->ip4_output_tap_node_index != ~0)
	{
	  if (im->ip4_output_tap_queue_index == ~0)
	    {
	      im->ip4_output_tap_queue_index =
		vlib_frame_queue_main_init (im->ip4_output_tap_node_index, 0);
	    }
	  tap_inject_enable_ip4_output (sw_if_index, 1);
	}
      else
	{
	  error = clib_error_return (0, "ip4-output-tap-inject feature not found");
	}
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (tap_inject_ip4_output_cli, static) = {
  .path = "tap-inject enable-ip4-output interface",
  .short_help = "tap-inject enable-ip4-output interface <interface> [del]",
  .function = tap_inject_enable_ip4_output_cli,
};

static clib_error_t *
tap_inject_map_interface_cli(vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 src_sw_if_index = ~0;
  u32 dst_sw_if_index = ~0;
  i32 is_del = 0;
  clib_error_t *error = 0;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%U %U",
                 unformat_vnet_sw_interface, vnet_get_main(), &src_sw_if_index,
                 unformat_vnet_sw_interface, vnet_get_main(), &dst_sw_if_index))
      ;
    else if (unformat(line_input, "del"))
      is_del = 1;
    else
    {
      error = clib_error_return(0, "unknown input '%U'",
                                format_unformat_error, line_input);
      goto done;
    }
  }

  if (src_sw_if_index == ~0)
  {
    error = clib_error_return(0, "Invalid source sw_if_index");
    goto done;
  }

  if (dst_sw_if_index == ~0)
  {
    error = clib_error_return(0, "Invalid destination sw_if_index");
    goto done;
  }

  if (is_del)
  {
    tap_inject_map_interface_delete(src_sw_if_index, dst_sw_if_index);
  }
  else
  {
    tap_inject_map_interface_set(src_sw_if_index, dst_sw_if_index);
  }

done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(tap_inject_map_interface_cmd, static) = {
    .path = "tap-inject map interface",
    .short_help = "tap-inject map interface <interface_src> <interface_dst> [del]",
    .function = tap_inject_map_interface_cli,
};

static clib_error_t *
show_tap_inject_map_interface_cli (vlib_main_t * vm, unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  vnet_main_t * vnet_main = vnet_get_main ();
  tap_inject_main_t * im = tap_inject_get_main ();
  int i;

  if (tap_inject_is_config_disabled ())
    {
      vlib_cli_output (vm, "tap-inject is disabled in config.\n");
      return 0;
    }

  if (!tap_inject_is_enabled ())
    {
      vlib_cli_output (vm, "tap-inject is not enabled.\n");
      return 0;
    }

  for (i = 0; i < vec_len(im->sw_if_index_to_sw_if_index); i++)
    {
      if (im->sw_if_index_to_sw_if_index[i] == ~0)
        continue;

      vlib_cli_output (vm, "%U -> %U",
            format_vnet_sw_interface_name, vnet_main,
            vnet_get_sw_interface (vnet_main, i),
            format_vnet_sw_interface_name, vnet_main,
            vnet_get_sw_interface (vnet_main, im->sw_if_index_to_sw_if_index[i]));
    }

  return 0;
}

VLIB_CLI_COMMAND (show_tap_inject_map_interface_cmd, static) = {
  .path = "show tap-inject map interface",
  .short_help = "show tap-inject map interface",
  .function = show_tap_inject_map_interface_cli,
};

#endif /* FLEXIWAN_FEATURE */


static clib_error_t *
tap_inject_config (vlib_main_t * vm, unformat_input_t * input)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
        im->flags |= TAP_INJECT_F_CONFIG_ENABLE;

      else if (unformat (input, "disable"))
        im->flags |= TAP_INJECT_F_CONFIG_DISABLE;

      else if (unformat (input, "netlink-only"))
        im->flags |= TAP_INJECT_F_CONFIG_NETLINK;

      else if (unformat (input, "debug"))
        im->flags |= TAP_INJECT_F_DEBUG_ENABLE;

      else
        return clib_error_return (0, "syntax error `%U'",
                                  format_unformat_error, input);
    }

  if (tap_inject_is_config_enabled () && tap_inject_is_config_disabled ())
    return clib_error_return (0,
              "tap-inject cannot be both enabled and disabled.");

  return 0;
}

VLIB_CONFIG_FUNCTION (tap_inject_config, "tap-inject");

/*
  This CLI command is used in the form of 'tap-inject map tap ppp0/ifindex tun0' in PPPoE feature.
  As a result all the routes installed against pppX interface in Linux are mapped inside VPP against tun0.
*/
static clib_error_t *
tap_inject_map_tap_if_index_to_sw_if_index_cli(vlib_main_t *vm, unformat_input_t *input,
                                               vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 tap_if_index = ~0;
  u32 sw_if_index = ~0;
  i32 is_del = 0;
  clib_error_t *error = 0;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%u %U",
                 &tap_if_index,
                 unformat_vnet_sw_interface, vnet_get_main(), &sw_if_index))
      ;
    else if (unformat(line_input, "del"))
      is_del = 1;
    else
    {
      error = clib_error_return(0, "unknown input '%U'",
                                format_unformat_error, line_input);
      goto done;
    }
  }

  if (sw_if_index == ~0)
  {
    error = clib_error_return(0, "Invalid sw_if_index");
    goto done;
  }

  if (tap_if_index == ~0)
  {
    error = clib_error_return(0, "Invalid tap_if_index");
    goto done;
  }

  if (is_del)
  {
    tap_inject_unmap_tap_if_index_to_sw_if_index(tap_if_index);
  }
  else
  {
    tap_inject_map_tap_if_index_to_sw_if_index(tap_if_index, sw_if_index);
  }

done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(tap_inject_map_tap_cmd, static) = {
    .path = "tap-inject map tap",
    .short_help = "tap-inject map tap <tap_if_index> <interface> [del]",
    .function = tap_inject_map_tap_if_index_to_sw_if_index_cli,
};
