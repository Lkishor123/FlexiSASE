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
 *   - add support in fragmented packets designated for TAP
 *   - fix b->current to enable packets received on L2GRE to be pushed into TAP
 *   - enable VxLan decapsulation before packets are pushed into TAP
 *
 *  List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *   - nat-tap-inject-output: Support to NAT packets received from tap
 *   interface before being put on wire
 *   - enable_acl_based_classification: Classifies packet using classifier_acls
 *   plugin. The exported classifier_acls plugin API is used to perform the
 *   classification function.
 */

/*
   Details of nat-tcp-inject-output feature: This feature enables forwarding
   packets received from tap interface to ip4-output arc so it gets the NAT
   rules configured on the interface. For worker thread scenario, packets is
   passed to ip4-output arc using frame queues support provided by VPP. Directly
   passing packet (without frame queues) to node creates NAT entries in
   vpp_main thread and the return packet fails in NAT lookup. CLI support has
   been added to enable ip4-output forward on a per interface basis
 */

#include "tap_inject.h"

#include <netinet/in.h>
#include <vlib/vlib.h>
#ifdef FLEXIWAN_FIX
#include <sys/uio.h>
#endif /* FLEXIWAN_FIX */
#include <vnet/ethernet/arp_packet.h>
#include <linux/if_tun.h>

vlib_node_registration_t tap_inject_rx_node;
vlib_node_registration_t tap_inject_tx_node;
vlib_node_registration_t tap_inject_neighbor_node;

enum {
#ifndef FLEXIWAN_FEATURE   /* enable VRRP */
  NEXT_NEIGHBOR_ARP,
#endif
  NEXT_NEIGHBOR_ICMP6,
};

#ifdef FLEXIWAN_FEATURE   /* enable VRRP - redirect VR IP ICMP back to VPP */
enum {
  NEXT_TX_IP4_ICMP_INPUT,
};
#endif

/**
 * @brief Dynamically added tap_inject DPO type
 */
dpo_type_t tap_inject_dpo_type;

/* increment TTL & update checksum.
   Works either endian, so no need for byte swap. */
static_always_inline void
ip4_ttl_inc (vlib_buffer_t * b, ip4_header_t * ip)
{
  i32 ttl;
  u32 checksum;
  if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED))
    return;

  ttl = ip->ttl;

  checksum = ip->checksum - clib_host_to_net_u16 (0x0100);
  checksum += checksum >= 0xffff;

  ip->checksum = checksum;
  ttl += 1;
  ip->ttl = ttl;
#ifdef FLEXIWAN_FIX
  if (ip->checksum)
    ASSERT (ip4_header_checksum_is_valid (ip));
#else
  ASSERT (ip4_header_checksum_is_valid (ip));
#endif
}

#ifdef FLEXIWAN_FIX
static inline void
tap_inject_tap_send_buffer (vlib_main_t * vm, int fd, vlib_buffer_t * b)
{
  struct iovec iov;
  ssize_t n_bytes;
  u8 *    reassembled_buffer = 0;

  iov.iov_base = vlib_buffer_get_current (b);
  iov.iov_len = b->current_length;

  // Handle fragmented packet:
  // Calculate total lenght, allocate buffer and copy all fragments into it.
  // TODO: use static buffer per thread.
  /* Handle fragmented packet */
  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
  {
    u16             total_length = 0;
    vlib_buffer_t * b_curr = b;
    u8 *            p_buff;

    while (b_curr->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      total_length += b_curr->current_length;
      b_curr = vlib_get_buffer (vm, b_curr->next_buffer);
    }
    total_length += b_curr->current_length;

    reassembled_buffer = clib_mem_alloc (total_length);
    if (reassembled_buffer == 0)
    {
      clib_warning ("clib_mem_alloc (total_length=%d)failed", total_length);
      return;
    }

    b_curr = b;
    p_buff = reassembled_buffer;
    do
    {
      clib_memcpy_fast(p_buff, b_curr->data + b_curr->current_data, b_curr->current_length);
      p_buff += b_curr->current_length;
    } while ((b_curr->flags & VLIB_BUFFER_NEXT_PRESENT) &&
       (b_curr = vlib_get_buffer (vm, b_curr->next_buffer)));

    iov.iov_base = reassembled_buffer;
    iov.iov_len  = total_length;
  }

  n_bytes = writev (fd, &iov, 1);

  if (n_bytes < 0)
    clib_warning ("writev failed");
  // Handle fragmented packet
  //else if (n_bytes < b->current_length || b->flags & VLIB_BUFFER_NEXT_PRESENT)
  else if (n_bytes < b->current_length)
    clib_warning ("buffer truncated");

  if (reassembled_buffer)
    clib_mem_free(reassembled_buffer);
}
#else
static inline void
tap_inject_tap_send_buffer (int fd, vlib_buffer_t * b)
{
  struct iovec iov;
  ssize_t n_bytes;

  iov.iov_base = vlib_buffer_get_current (b);
  iov.iov_len = b->current_length;

  n_bytes = writev (fd, &iov, 1);

  if (n_bytes < 0)
    clib_warning ("writev failed");
  else if (n_bytes < b->current_length || b->flags & VLIB_BUFFER_NEXT_PRESENT)
    clib_warning ("buffer truncated");
}
#endif /* FLEXIWAN_FIX */

#ifdef FLEXIWAN_FIX
static int
is_vrrp_buffer(vlib_buffer_t * b)
{
  ethernet_header_t * eth        = vlib_buffer_get_current (b);
  u16                 ether_type = htons (eth->type);
  ip4_header_t *      ip;
  icmp46_header_t *   icmp;
  tap_inject_main_t * im;
  u32                 index;

  if (ether_type != ETHERNET_TYPE_IP4)
    return 0;

  ip = (ip4_header_t *)(eth + 1);
  if (ip->protocol != IP_PROTOCOL_ICMP)
    return 0;

  icmp = (icmp46_header_t *)(ip + 1);
  if (icmp->type != ICMP4_echo_request)
    return 0;

  im    = tap_inject_get_main ();
  index = vec_search (im->vrrp_vr_ip4s, ip->dst_address.as_u32);
  if (index == ~0)
    return 0;

  return 1;
}
#endif /*#ifdef FLEXIWAN_FIX*/

static uword
tap_inject_tx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  vlib_buffer_t * b;
  u32 * pkts;
  u32 fd;
  u32 i;
#ifdef FLEXIWAN_FIX
  u32 bi;
  u32 next_index = node->cached_next_index;
  u32 next;
  u32 n_left;
  u32 * to_next;
#endif /*#ifdef FLEXIWAN_FIX*/

  pkts = vlib_frame_vector_args (f);

  for (i = 0; i < f->n_vectors; ++i)
    {
      bi = pkts[i];
      b = vlib_get_buffer (vm, bi);

      fd = tap_inject_lookup_tap_fd (vnet_buffer (b)->sw_if_index[VLIB_RX]);
      if (fd == ~0)
        continue;

      /* Re-wind the buffer to the start of the Ethernet header. */
#ifdef FLEXIWAN_FIX
      // The '-b->current_data' assumes that packet is regular L2-L3-APP packet.
      // This is not true in case of l2gre.
      // The packet that comes out of L2-GRE Tunnel (ipsec-gre node)
      // has L2-IPSEC_ESP-L2-L3-APP structure
      // vlib_buffer_advance (b, -b->current_data);
      // The adjustment is needed for TAP and not for TUN. As far as TUN works
      // with pure IP packets with ethernet header on top.
      // Note that currently TUN is used for Flexiwan peer tunnels only.
      if (tap_inject_type_check(vnet_buffer (b)->sw_if_index[VLIB_RX], TAP_INJECT_TAP))
      {
        if (tap_inject_type_check(vnet_buffer (b)->sw_if_index[VLIB_RX], TAP_INJECT_VLAN))
        {
          vlib_buffer_advance (b, -sizeof(ethernet_vlan_header_t));
        }
        vlib_buffer_advance (b, -sizeof(ethernet_header_t));
      }

      /* Packets that are designated to VRRP virtual IP should not be pushed
         into Linux, as the last will discard them. Linux is unaware of virtual
         IP and multicast MAC address managed by the VRRP plugin of VPP.
         Push these packets back into VPP.
      */
      if (is_vrrp_buffer(b))
      {
        next = NEXT_TX_IP4_ICMP_INPUT;
        vlib_buffer_advance (b, sizeof (ethernet_header_t));
        vlib_get_next_frame (vm, node, next_index, to_next, n_left);
        *(to_next++) = bi;
        --n_left;

        vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                        n_left, bi, next);
        vlib_put_next_frame (vm, node, next_index, n_left);
        continue;
      }

      tap_inject_tap_send_buffer (vm, fd, b);
#endif /* FLEXIWAN_FIX */
      vlib_buffer_free (vm, &bi, 1);
    }

  return f->n_vectors;
}

VLIB_REGISTER_NODE (tap_inject_tx_node) = {
  .function = tap_inject_tx,
  .name = "tap-inject-tx",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
#ifdef FLEXIWAN_FEATURE   /* enable VRRP - redirect Virtual IP ICMP packets back to VPP */
  .n_next_nodes = 1,
  .next_nodes = {
    [NEXT_TX_IP4_ICMP_INPUT] = "ip4-icmp-input",
  },
#endif /*#ifndef FLEXIWAN_FEATURE*/
};

#ifdef FLEXIWAN_FIX
/*
  The purpose of this node is to intercept PPPoE packets in VPP and push them into Linux.

  Firstly, the packet is received on VPP WAN interface and is intercepted by the
  due to ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_X).
  And secondly, the node pushes the packet into Linux through the WAN TAP interface.

  There the packet is de-capsulated and pushed by Linux back into the WAN TAP interface.
*/
static uword
tap_inject_pppoe_tx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  vlib_buffer_t * b;
  u32 * pkts;
  u32 fd;
  u32 i;

  pkts = vlib_frame_vector_args (f);

  for (i = 0; i < f->n_vectors; ++i)
    {
      b = vlib_get_buffer (vm, pkts[i]);

      fd = tap_inject_lookup_tap_fd (vnet_buffer (b)->sw_if_index[VLIB_RX]);
      if (fd == ~0) {
        clib_warning("FD is unknown, VLIB_RX %u", vnet_buffer (b)->sw_if_index[VLIB_RX]);
        continue;
    }

      vlib_buffer_advance (b, -sizeof(ethernet_header_t));
      tap_inject_tap_send_buffer (vm, fd, b);
    }

  vlib_buffer_free (vm, pkts, f->n_vectors);
  return f->n_vectors;
}

VLIB_REGISTER_NODE (tap_inject_pppoe_tx_node) = {
  .function = tap_inject_pppoe_tx,
  .name = "tap-inject-pppoe-tx",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

/* *INDENT-OFF* */
VNET_FEATURE_INIT (tap_inject_pppoe_tx_node, static) =
{
  .arc_name = "device-input",
  .node_name = "tap-inject-pppoe-tx",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

VNET_FEATURE_INIT (tap_inject_tx_node, static) = {
  .arc_name = "ip4-punt",
  .node_name = "tap-inject-tx",
  .runs_before = VNET_FEATURES("error-punt"),
};

VLIB_REGISTER_NODE (ip6_tap_inject_tx_node) = {
  .function = tap_inject_tx,
  .name = "ip6-tap-inject-tx",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VNET_FEATURE_INIT (ip6_tap_inject_tx_node, static) = {
  .arc_name = "ip6-punt",
  .node_name = "ip6-tap-inject-tx",
  .runs_before = VNET_FEATURES("error-punt"),
};
#endif /* FLEXIWAN_FIX */

static uword
tap_inject_neighbor (vlib_main_t * vm,
                     vlib_node_runtime_t * node, vlib_frame_t * f)
{
  vlib_buffer_t * b;
  u32 * pkts;
  u32 fd;
  u32 i;
  u32 bi;
  u32 next_index = node->cached_next_index;
  u32 next = ~0;
  u32 n_left;
  u32 * to_next;

  pkts = vlib_frame_vector_args (f);

  for (i = 0; i < f->n_vectors; ++i)
    {
      bi = pkts[i];
      b = vlib_get_buffer (vm, bi);

      fd = tap_inject_lookup_tap_fd (vnet_buffer (b)->sw_if_index[VLIB_RX]);
      if (fd == ~0)
        {
          vlib_buffer_free (vm, &bi, 1);
          continue;
        }

      next = ~0;

      /* Re-wind the buffer to the start of the Ethernet header. */
#ifdef FLEXIWAN_FIX
      // The '-b->current_data' assumes that packet is regular L2-L3-APP packet.
      // This is not true in case of l2gre.
      // The packet that comes out of L2-GRE Tunnel (ipsec-gre node)
      // has L2-IPSEC_ESP-L2-L3-APP structure
      // vlib_buffer_advance (b, -b->current_data);
      vlib_buffer_advance (b, -sizeof(ethernet_header_t));

      // In case of subinterface, i.e. VLAN, we adjust for a vlan header
      if (tap_inject_type_check(vnet_buffer (b)->sw_if_index[VLIB_RX], TAP_INJECT_VLAN))
        vlib_buffer_advance (b, -sizeof(ethernet_vlan_header_t));

      tap_inject_tap_send_buffer (vm, fd, b);
#endif /* FLEXIWAN_FIX */
      /* Send the buffer to a neighbor node too? */
      {
        ethernet_header_t * eth = vlib_buffer_get_current (b);
        u16 ether_type = htons (eth->type);

        if (ether_type == ETHERNET_TYPE_ARP)
          {
            ethernet_arp_header_t * arp = (void *)(eth + 1);

            if (arp->opcode == ntohs (ETHERNET_ARP_OPCODE_reply))
#ifdef FLEXIWAN_FEATURE   /* enable VRRP */
                vnet_feature_next (&next, b);
#else
              next = NEXT_NEIGHBOR_ARP;
#endif
          }
        else if (ether_type == ETHERNET_TYPE_IP6)
          {
            ip6_header_t * ip = (void *)(eth + 1);
            icmp46_header_t * icmp = (void *)(ip + 1);

            if (ip->protocol == IP_PROTOCOL_ICMP6 &&
                icmp->type == ICMP6_neighbor_advertisement)
              next = NEXT_NEIGHBOR_ICMP6;
          }
      }

      if (next == ~0)
        {
          vlib_buffer_free (vm, &bi, 1);
          continue;
        }

      /* ARP and ICMP6 expect to start processing after the Ethernet header. */
      vlib_buffer_advance (b, sizeof (ethernet_header_t));

      vlib_get_next_frame (vm, node, next_index, to_next, n_left);

      *(to_next++) = bi;
      --n_left;

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                       n_left, bi, next);
      vlib_put_next_frame (vm, node, next_index, n_left);
    }

  return f->n_vectors;
}

VLIB_REGISTER_NODE (tap_inject_neighbor_node) = {
  .function = tap_inject_neighbor,
  .name = "tap-inject-neighbor",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
#ifndef FLEXIWAN_FEATURE   /* enable VRRP */
  .n_next_nodes = 2,
  .next_nodes = {
    [NEXT_NEIGHBOR_ARP] = "arp-input",
    [NEXT_NEIGHBOR_ICMP6] = "icmp6-neighbor-solicitation",
  },
#else
  .n_next_nodes = 1,
  .next_nodes = {
    [NEXT_NEIGHBOR_ICMP6] = "icmp6-neighbor-solicitation",
  },
#endif /*#ifndef FLEXIWAN_FEATURE*/
};

/* Ensure the "arp-input -> vrrp4-arp-input -> tap-inject-neighbor" path.
   No other nodes should be in the middle, so tap-inject-neighbor will
   intercept and will push into Linux all ARP traffic except the VRRP packets!
   Just like it was before we added support in VRRP.
*/
VNET_FEATURE_INIT (tap_inject_arp_feat_node, static) =
{
  .arc_name = "arp",
  .node_name = "tap-inject-neighbor",
  .runs_after = VNET_FEATURES ("vrrp4-arp-input"),
  .runs_before = VNET_FEATURES ("arp-reply"),
};


#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
static inline u32
tap_rx_ip4_output_tap_worker_offset (tap_inject_main_t * tm, ip4_header_t * ip4)
{
  u32 hash;

  hash = ip4->src_address.as_u32 + (ip4->src_address.as_u32 >> 8) +
    (ip4->src_address.as_u32 >> 16) + (ip4->src_address.as_u32 >> 24);

  if (PREDICT_TRUE (is_pow2 (tm->num_workers)))
    return hash & (tm->num_workers - 1);
  else
    return hash % tm->num_workers;
}
#endif /* FLEXIWAN_FEATURE */

#define MTU 1500
#define MTU_BUFFERS ((MTU + VLIB_BUFFER_DEFAULT_DATA_SIZE - 1) / VLIB_BUFFER_DEFAULT_DATA_SIZE)
#define NUM_BUFFERS_TO_ALLOC 32

static inline uword
tap_rx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f, int fd)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  u32 sw_if_index;
  struct iovec iov[MTU_BUFFERS];
  u32 bi[MTU_BUFFERS];
  vlib_buffer_t * b;
  ssize_t n_bytes;
  ssize_t n_bytes_left;
  u32 i, j;

  sw_if_index = tap_inject_lookup_sw_if_index_from_tap_fd (fd);
  if (sw_if_index == ~0)
    {
      clib_warning ("failed to lookup sw_if_index, tap_fd %d", fd);
      return 0;
    }

  /* Allocate buffers in bulk when there are less than enough to rx an MTU. */
  if (vec_len (im->rx_buffers) < MTU_BUFFERS)
    {
      u32 len = vec_len (im->rx_buffers);

      len = vlib_buffer_alloc_on_numa (vm,
            &im->rx_buffers[len], NUM_BUFFERS_TO_ALLOC,
            vm->numa_node);

      _vec_len (im->rx_buffers) += len;

      if (vec_len (im->rx_buffers) < MTU_BUFFERS)
        {
          clib_warning ("failed to allocate buffers");
          return 0;
        }
    }

  /* Fill buffers from the end of the list to make it easier to resize. */
  for (i = 0, j = vec_len (im->rx_buffers) - 1; i < MTU_BUFFERS; ++i, --j)
    {
      vlib_buffer_t * b;

      bi[i] = im->rx_buffers[j];

      b = vlib_get_buffer (vm, bi[i]);

      iov[i].iov_base = b->data;
      iov[i].iov_len = VLIB_BUFFER_DEFAULT_DATA_SIZE;
    }

  n_bytes = readv (fd, iov, MTU_BUFFERS);
  if (n_bytes < 0)
    {
      clib_warning ("readv failed");
      return 0;
    }

  b = vlib_get_buffer (vm, bi[0]);

  // The Flexiwan peer feature pushes Linux packets into
  // ip4-input node and not into loopX-output.
  // As a result, they go through the forwarding, where TTL is decremented.
  // As OSPF negotiation rides on multicast packets with TTL=1,
  // the forwarding decrements TLL to zero and drops the packets.
  // To prevent this, we just set TTL to be 2, so OSPF packets for peer tunnels
  // will be not dropped.
  if (!tap_inject_is_enabled_ip4_output(sw_if_index) &&
      tap_inject_type_check(sw_if_index, TAP_INJECT_TUN)) {
    ip4_header_t *ip = vlib_buffer_get_current (b);
    if (PREDICT_FALSE (ip->protocol == IP_PROTOCOL_OSPF && ip->ttl == 1))
    {
      ip4_ttl_inc (b, ip);
    }
  }

  vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
  // TX interface index is not needed for packets inserted in 'ip4-input' node
  // if 'enable-ip4-output' feature is disabled.
  if (!tap_inject_is_enabled_ip4_output(sw_if_index) &&
      tap_inject_type_check(sw_if_index, TAP_INJECT_TUN)) {
    vnet_buffer (b)->sw_if_index[VLIB_TX] = (u32) ~ 0;
  }
  // TX interface index is needed for packets inserted in 'ip4-output-tap-inject' node
  // if 'enable-ip4-output' is enabled.
  else {
    vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;
  }

  n_bytes_left = n_bytes - VLIB_BUFFER_DEFAULT_DATA_SIZE;

  if (n_bytes_left > 0)
    {
      b->total_length_not_including_first_buffer = n_bytes_left;
      b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
    }

  b->current_length = n_bytes;
  b->error = node->errors[0];
#ifdef FLEXIWAN_FEATURE  /* enable_acl_based_classification */
  if (im->classifier_acls_fn)
    {
      u8 is_ip6 = 0;
      if (tap_inject_type_check(sw_if_index, TAP_INJECT_TAP))
	{
	  ethernet_header_t *eh = vlib_buffer_get_current (b);
	  vlib_buffer_advance (b, sizeof(ethernet_header_t));
	  u16 ether_type = clib_net_to_host_u16 (eh->type);
	  if (ether_type == ETHERNET_TYPE_IP6)
	    {
	      is_ip6 = 1;
	    }
	  im->classifier_acls_fn (b, sw_if_index, is_ip6, NULL, NULL);
          vlib_buffer_advance (b, -sizeof(ethernet_header_t));
	}
      else if (tap_inject_type_check(sw_if_index, TAP_INJECT_TUN))
	{
          ip4_header_t *ip = vlib_buffer_get_current (b);
	  if ((ip->ip_version_and_header_length & 0xF0) == 0x60)
	    {
	      is_ip6 = 1;
	    }
	  im->classifier_acls_fn (b, sw_if_index, is_ip6, NULL, NULL);
	}
    }
#endif /* FLEXIWAN_FEATURE - enable_acl_based_classification */

  /* If necessary, configure any remaining buffers in the chain. */
  for (i = 1; n_bytes_left > 0 && i < MTU_BUFFERS; ++i, n_bytes_left -= VLIB_BUFFER_DEFAULT_DATA_SIZE)
    {
      b = vlib_get_buffer (vm, bi[i - 1]);
      b->current_length = VLIB_BUFFER_DEFAULT_DATA_SIZE;
      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b->next_buffer = bi[i];

      b = vlib_get_buffer (vm, bi[i]);
      b->current_length = n_bytes_left;
    }

  _vec_len (im->rx_buffers) -= i;

#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
  vnet_sw_interface_t * sw = vnet_get_sw_interface_or_null (vnet_get_main (), sw_if_index);
  vnet_hw_interface_t * hw = vnet_get_hw_interface (vnet_get_main (), sw->hw_if_index);
  u32 output_handoff_index = hw->output_node_index;
  u32 ip4_output_set = 0;
  u16 ip4_output_tap_thread_index;
  ip4_header_t *ip4 = NULL;

  if (tap_inject_type_check(sw_if_index, TAP_INJECT_TAP)) {
    ethernet_header_t *eh = vlib_buffer_get_current (b);
    if (clib_net_to_host_u16 (eh->type) == ETHERNET_TYPE_IP4) {
      if (tap_inject_is_enabled_ip4_output(sw_if_index)) {
        ip4 = vlib_buffer_get_current (b) + sizeof (ethernet_header_t);
        vnet_buffer (b)->ip.save_rewrite_length = sizeof (ethernet_header_t);
        ip4_output_set = 1;
      }
    }
    else if (clib_net_to_host_u16 (eh->type) == ETHERNET_TYPE_VLAN) {
      ethernet_vlan_header_t *vlan = vlib_buffer_get_current (b) + sizeof(ethernet_header_t);
      if (clib_net_to_host_u16 (vlan->type) == ETHERNET_TYPE_IP4) {
        u16 vlan_id = clib_net_to_host_u16 (vlan->priority_cfi_and_id);
        u32 vlan_sw_if_index = tap_inject_vlan_sw_if_index_get(vlan_id, sw_if_index);
        if (tap_inject_is_enabled_ip4_output(vlan_sw_if_index)) {
          ip4 = vlib_buffer_get_current (b) + sizeof (ethernet_header_t) + sizeof(ethernet_vlan_header_t);
          vnet_buffer (b)->ip.save_rewrite_length = sizeof (ethernet_header_t) + sizeof(ethernet_vlan_header_t);
          ip4_output_set = 1;
          vnet_buffer (b)->sw_if_index[VLIB_TX] = vlan_sw_if_index;
        }
      }
    }
  }

  if (tap_inject_type_check(sw_if_index, TAP_INJECT_TUN)) {
    if (tap_inject_is_enabled_ip4_output(sw_if_index)) {
      ip4 = vlib_buffer_get_current (b);
      if ((ip4->ip_version_and_header_length & 0xF0) == 0x40) {
        ip4_output_set = 1;
      }
    }
  }

  if (ip4_output_set) {
    ip4_output_tap_thread_index = im->ip4_output_tap_first_worker_index +
                                  tap_rx_ip4_output_tap_worker_offset (im, ip4);
    output_handoff_index = im->ip4_output_tap_node_index;
  }

  if ((ip4_output_set) && (im->num_workers))
    {
      vlib_buffer_enqueue_to_thread (vm, im->ip4_output_tap_queue_index, &bi[0],
				     &ip4_output_tap_thread_index, 1, 1);
    }
  else
    {
      vlib_frame_t * new_frame;
      u32 * to_next;
      new_frame = vlib_get_frame_to_node (vm, output_handoff_index);
      to_next = vlib_frame_vector_args (new_frame);
      to_next[0] = bi[0];
      new_frame->n_vectors = 1;

      // Packets are inserted into 'ip4-input' node if 'enable-ip4-output' feature is disabled.
      if (!tap_inject_is_enabled_ip4_output(sw_if_index) &&
          tap_inject_type_check(sw_if_index, TAP_INJECT_TUN)) {
        vlib_put_frame_to_node (vm, im->ip4_input_node_index, new_frame);
      }
      // Packets are inserted into 'ip4-output-tap-inject' node if 'enable-ip4-output' feature is enabled.
      else {
        vlib_put_frame_to_node (vm, output_handoff_index, new_frame);
      }
    }
#else
  /* Get the packet to the output node. */
  {
    vnet_hw_interface_t * hw;
    vlib_frame_t * new_frame;
    u32 * to_next;

    hw = vnet_get_hw_interface (vnet_get_main (), sw_if_index);

    new_frame = vlib_get_frame_to_node (vm, hw->output_node_index);
    to_next = vlib_frame_vector_args (new_frame);
    to_next[0] = bi[0];
    new_frame->n_vectors = 1;

    vlib_put_frame_to_node (vm, hw->output_node_index, new_frame);
  }

#endif /* FLEXIWAN_FEATURE */

  return 1;
}

static uword
tap_inject_rx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  u32 * fd;
  uword count = 0;

  vec_foreach (fd, im->rx_file_descriptors)
    {
      if (tap_rx (vm, node, f, *fd) != 1)
        {
          clib_warning ("rx failed");
          count = 0;
          break;
        }
      ++count;
    }

  vec_free (im->rx_file_descriptors);

  return count;
}

VLIB_REGISTER_NODE (tap_inject_rx_node) = {
  .function = tap_inject_rx,
  .name = "tap-inject-rx",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};

/**
 * @brief no-op lock function.
 */
static void
tap_inject_dpo_lock (dpo_id_t * dpo)
{
}

/**
 * @brief no-op unlock function.
 */
static void
tap_inject_dpo_unlock (dpo_id_t * dpo)
{
}

u8 *
format_tap_inject_dpo (u8 * s, va_list * args)
{
  return (format (s, "tap-inject:[%d]", 0));
}

const static dpo_vft_t tap_inject_vft = {
  .dv_lock = tap_inject_dpo_lock,
  .dv_unlock = tap_inject_dpo_unlock,
  .dv_format = format_tap_inject_dpo,
};

const static char *const tap_inject_tx_nodes[] = {
  "tap-inject-tx",
  NULL,
};

const static char *const *const tap_inject_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = tap_inject_tx_nodes,
  [DPO_PROTO_IP6] = tap_inject_tx_nodes,
};

static clib_error_t *
tap_inject_init (vlib_main_t * vm)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  im->rx_node_index = tap_inject_rx_node.index;
  im->tx_node_index = tap_inject_tx_node.index;
  im->neighbor_node_index = tap_inject_neighbor_node.index;

  tap_inject_dpo_type = dpo_register_new_type (&tap_inject_vft, tap_inject_nodes);

  vec_alloc (im->rx_buffers, NUM_BUFFERS_TO_ALLOC);
  vec_reset_length (im->rx_buffers);

#ifdef FLEXIWAN_FEATURE /* nat-tap-inject-output */
  im->ip4_output_tap_node_index = ~0;
  im->ip4_output_tap_queue_index = ~0;
  im->ip4_input_node_index = ~0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword *threads = hash_get_mem (tm->thread_registrations_by_name, "workers");
  if (threads)
    {
      vlib_thread_registration_t *worker;
      worker = (vlib_thread_registration_t *) threads[0];
      if (worker)
        {
          im->ip4_output_tap_first_worker_index = worker->first_index;
          im->num_workers = worker->count;
        }
    }

  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *)"ip4-output-tap-inject");
  if (node)
    {
      im->ip4_output_tap_node_index = node->index;
    }

  node = vlib_get_node_by_name (vm, (u8 *)"ip4-input");
  if (node)
    {
      im->ip4_input_node_index = node->index;
    }

#endif /* FLEXIWAN_FEATURE */

#ifdef FLEXIWAN_FEATURE  /* enable_acl_based_classification */
  im->classifier_acls_fn = vlib_get_plugin_symbol
    ("classifier_acls_plugin.so", "classifier_acls_classify_packet_api");
#endif /* FLEXIWAN_FEATURE - enable_acl_based_classification */

#ifdef FLEXIWAN_FEATURE
  im->vrrp_vr_ip4s = 0;
#endif

  im->vlan_to_sw_if_index = hash_create (0, sizeof (u32));

  return 0;
}

VLIB_INIT_FUNCTION (tap_inject_init);
