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
 *  Copyright (C) 2021 flexiWAN Ltd.
 *  List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *   - nat-tap-inject-output: Support to NAT packets received from tap
 *     interface before being put on wire
 *   - show tap-inject [name|tap|sw_if_index]: dump tap-inject info for specific interface
 *   - enable_acl_based_classification: Classifies packet using classifier_acls
 *   plugin. The exported classifier_acls plugin API is used to perform the
 *   classification function.
 *   - fix memory leak with clib_file_add() on tap inject/delete
 */

#ifndef _TAP_INJECT_H
#define _TAP_INJECT_H

#include <vppinfra/clib.h>    // Bring FLEXIWAN_FIX and FLEXIWAN_FEATURE definitions
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip.h>

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

extern vnet_hw_interface_class_t tun_device_hw_interface_class;

#ifdef FLEXIWAN_FEATURE /* enable_acl_based_classification */
typedef u32 (*classifier_acls_classify_packet_fn)
	(vlib_buffer_t *b, u32 sw_if_index, u8 is_ip6, u32 *out_acl_index,
	 u32 *out_rule_index);
#endif /* FLEXIWAN_FEATURE - enable_acl_based_classification */
typedef struct {
  u16 vlan;
  u32 parent_sw_if_index;
} tap_inject_vlan_key_internal_t;

typedef union {
  uword k;
  tap_inject_vlan_key_internal_t key;
} tap_inject_vlan_key_t;

typedef struct {
  /*
   * tap-inject can be enabled or disabled in config file or during runtime.
   * When disabled in config, it is not possible to enable during runtime.
   *
   * When the netlink-only option is used, netlink configuration is monitored
   * and mirrored to the data plane but no traffic is passed between the host
   * and the data plane.
   */
#define TAP_INJECT_F_CONFIG_ENABLE  (1U << 0)
#define TAP_INJECT_F_CONFIG_DISABLE (1U << 1)
#define TAP_INJECT_F_CONFIG_NETLINK (1U << 2)
#define TAP_INJECT_F_ENABLED        (1U << 3)
#define TAP_INJECT_F_DEBUG_ENABLE   (1U << 4)

  u32 flags;

  u32 * sw_if_index_to_tap_fd;
  u32 * sw_if_index_to_tap_if_index;
  u32 * tap_fd_to_sw_if_index;
  u32 * tap_if_index_to_sw_if_index;
  /*
   * sw_if_index_to_sw_if_index array is used to map between loopX and ipipX interfaces.
   * It is used in Flexiwan peer tunnel feature to install ip routes from Linux.
   * Meaning that all routes created against loopX (vppX) in Linux will be installed in VPP against ipipX.
   */
  u32 * sw_if_index_to_sw_if_index;
#ifdef FLEXIWAN_FEATURE
  u8* * sw_if_index_to_tap_name; /*vector that maps sw_if_index into tap name*/
  uword * tap_if_index_by_name;  /*hash that maps tap name into tap index*/
  u32 * sw_if_index_to_clib_file_index;
  uword * vlan_to_sw_if_index;
  uword * sw_if_index_to_vlan;
#endif /* FLEXIWAN_FEATURE */

  u32 * interfaces_to_enable;
  u32 * interfaces_to_disable;

  u32 * rx_file_descriptors;

  u32 rx_node_index;
  u32 tx_node_index;
  u32 neighbor_node_index;

  u32 * rx_buffers;

#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
  u32 * sw_if_index_to_ip4_output;
  u32 ip4_output_tap_node_index;
  u32 ip4_output_tap_queue_index;
  u16 ip4_output_tap_first_worker_index;
  u16 num_workers;
#endif /* FLEXIWAN_FEATURE */

#ifdef FLEXIWAN_FEATURE /* enable_acl_based_classification */
  classifier_acls_classify_packet_fn classifier_acls_fn;
#endif /* FLEXIWAN_FEATURE - enable_acl_based_classification */
  u32 * type;
  u32 ip4_input_node_index;

#ifdef FLEXIWAN_FEATURE
  u32* vrrp_vr_ip4s;
#endif /* FLEXIWAN_FEATURE */
} tap_inject_main_t;


tap_inject_main_t * tap_inject_get_main (void);

#ifdef FLEXIWAN_FEATURE
void tap_inject_insert_tap (u32 sw_if_index, u32 tap_fd, u32 tap_if_index, u8* tap_if_name);
#else
void tap_inject_insert_tap (u32 sw_if_index, u32 tap_fd, u32 tap_if_index);
#endif /* FLEXIWAN_FEATURE */
void tap_inject_delete_tap (u32 sw_if_index);

void tap_inject_map_interface_set (u32 src_sw_if_index, u32 dst_sw_if_index);
void tap_inject_map_interface_delete (u32 src_sw_if_index, u32 dst_sw_if_index);
u32 tap_inject_map_interface_get (u32 sw_if_index);

u32 tap_inject_lookup_tap_fd (u32 sw_if_index);
u32 tap_inject_lookup_sw_if_index_from_tap_fd (u32 tap_fd);
u32 tap_inject_lookup_sw_if_index_from_tap_if_index (u32 tap_if_index);

void tap_inject_vlan_sw_if_index_add_del (u16 vlan, u32 parent_sw_if_index, u32 vlan_sw_if_index, u32 add);
u32 tap_inject_vlan_sw_if_index_get (u16 vlan, u32 parent_sw_if_index);


#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
u32 tap_inject_is_enabled_ip4_output (u32 sw_if_index);
void tap_inject_enable_ip4_output (u32 sw_if_index, u32 enable);
#endif /* FLEXIWAN_FEATURE */

#define TAP_INJECT_TAP     (1U << 0)
#define TAP_INJECT_TUN     (1U << 1)
#define TAP_INJECT_VLAN    (1U << 2)
#define TAP_INJECT_MAPPED  (1U << 3)

static inline int
tap_inject_debug_is_enabled (void)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  return !!(im->flags & TAP_INJECT_F_DEBUG_ENABLE);
}

static inline u32
tap_inject_type_check (u32 sw_if_index, u32 type)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  return (im->type[sw_if_index] & type) == type;
}

static inline u32
tap_inject_type_get (u32 sw_if_index)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  return im->type[sw_if_index];
}

static inline void
tap_inject_type_set (u32 sw_if_index, u32 type)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  vec_validate_init_empty (im->type, sw_if_index, 0);
  im->type[sw_if_index] |= type;

  if (tap_inject_debug_is_enabled())
    {
      clib_warning("sw_if_index: %d, type 0x%x", sw_if_index, im->type[sw_if_index]);
    }
}

static inline int
tap_inject_is_enabled (void)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  return !!(im->flags & TAP_INJECT_F_ENABLED);
}

static inline int
tap_inject_is_config_enabled (void)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  return !!(im->flags & TAP_INJECT_F_CONFIG_ENABLE);
}

static inline int
tap_inject_is_config_disabled (void)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  return !!(im->flags & TAP_INJECT_F_CONFIG_DISABLE);
}

/* Netlink */

void tap_inject_enable_netlink (void);


/* Tap */

clib_error_t * tap_inject_tap_connect (vnet_hw_interface_t * hw);
clib_error_t * tap_inject_tap_disconnect (u32 sw_if_index);

u8 * format_tap_inject_tap_name (u8 * s, va_list * args);

#endif /* _TAP_INJECT_H */
