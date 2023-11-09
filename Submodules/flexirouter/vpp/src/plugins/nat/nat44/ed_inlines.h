/*
 * simple nat plugin
 *
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 */

/*
 *  List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *   - session_recovery_on_nat_addr_flap : Prevent flushing of NAT sessions on
 *     NAT address flap. If same address gets added back, it shall ensure
 *     continuity of NAT sessions. On NAT interface address delete, the feature
 *     marks the flow as stale and activates it back if the same NAT address is
 *     added back on the interface. Feature is supported in
 *     nat44-ed-output-feature mode and can be enabled on a per interface basis
 *     via API/CLI
 *
 *   - nat_interface_specific_address_selection : Feature to select NAT address
 *     based on the output interface assigned to the packet. This ensures using
 *     respective interface address for NAT (Provides multiwan-dia support).
 *     The feature also has support to invalidate the NAT session on
 *     NAT-interface change due to routing decision changes.
 */

#ifndef __included_ed_inlines_h__
#define __included_ed_inlines_h__

#include <float.h>
#include <vppinfra/clib.h>
#include <nat/nat.h>
#include <nat/nat_inlines.h>

static_always_inline int
nat_ed_lru_insert (snat_main_per_thread_data_t * tsm,
		   snat_session_t * s, f64 now, u8 proto)
{
  dlist_elt_t *lru_list_elt;
  pool_get (tsm->lru_pool, lru_list_elt);
  s->lru_index = lru_list_elt - tsm->lru_pool;
  switch (proto)
    {
    case IP_PROTOCOL_UDP:
      s->lru_head_index = tsm->udp_lru_head_index;
      break;
    case IP_PROTOCOL_TCP:
      s->lru_head_index = tsm->tcp_trans_lru_head_index;
      break;
    case IP_PROTOCOL_ICMP:
      s->lru_head_index = tsm->icmp_lru_head_index;
      break;
    default:
      s->lru_head_index = tsm->unk_proto_lru_head_index;
      break;
    }
  clib_dlist_addtail (tsm->lru_pool, s->lru_head_index, s->lru_index);
  lru_list_elt->value = s - tsm->sessions;
  s->last_lru_update = now;
  return 1;
}

always_inline void
nat_ed_session_delete (snat_main_t * sm, snat_session_t * ses,
		       u32 thread_index, int lru_delete
		       /* delete from global LRU list */ )
{
  snat_main_per_thread_data_t *tsm = vec_elt_at_index (sm->per_thread_data,
						       thread_index);

  if (lru_delete)
    {
      clib_dlist_remove (tsm->lru_pool, ses->lru_index);
    }
  pool_put_index (tsm->lru_pool, ses->lru_index);
  pool_put (tsm->sessions, ses);
  vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			   pool_elts (tsm->sessions));

}

static_always_inline int
nat_lru_free_one_with_head (snat_main_t * sm, int thread_index,
			    f64 now, u32 head_index)
{
  snat_session_t *s = NULL;
  dlist_elt_t *oldest_elt;
  f64 sess_timeout_time;
  u32 oldest_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  oldest_index = clib_dlist_remove_head (tsm->lru_pool, head_index);
  if (~0 != oldest_index)
    {
      oldest_elt = pool_elt_at_index (tsm->lru_pool, oldest_index);
      s = pool_elt_at_index (tsm->sessions, oldest_elt->value);

      sess_timeout_time =
	s->last_heard + (f64) nat44_session_get_timeout (sm, s);
      if (now >= sess_timeout_time
	  || (s->tcp_closed_timestamp && now >= s->tcp_closed_timestamp))
	{
	  nat_free_session_data (sm, s, thread_index, 0);
	  nat_ed_session_delete (sm, s, thread_index, 0);
	  return 1;
	}
      else
	{
	  clib_dlist_addhead (tsm->lru_pool, head_index, oldest_index);
	}
    }
  return 0;
}

static_always_inline int
nat_lru_free_one (snat_main_t * sm, int thread_index, f64 now)
{
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  int rc = 0;
#define _(p)                                                       \
  if ((rc = nat_lru_free_one_with_head (sm, thread_index, now,     \
                                        tsm->p##_lru_head_index))) \
    {                                                              \
      return rc;                                                   \
    }
  _(tcp_trans);
  _(udp);
  _(unk_proto);
  _(icmp);
  _(tcp_estab);
#undef _
  return 0;
}

static_always_inline snat_session_t *
nat_ed_session_alloc (snat_main_t * sm, u32 thread_index, f64 now, u8 proto)
{
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  nat_lru_free_one (sm, thread_index, now);

  pool_get (tsm->sessions, s);
  clib_memset (s, 0, sizeof (*s));

  nat_ed_lru_insert (tsm, s, now, proto);

  s->ha_last_refreshed = now;
#ifdef FLEXIWAN_FEATURE
  /* Feature name: nat_interface_specific_address_selection */
  s->sw_if_index = ~0;
#endif
  vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			   pool_elts (tsm->sessions));
  return s;
}

// slow path
static_always_inline void
per_vrf_sessions_cleanup (u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions_t *per_vrf_sessions;
  u32 *to_free = 0, *i;

  vec_foreach (per_vrf_sessions, tsm->per_vrf_sessions_vec)
  {
    if (per_vrf_sessions->expired)
      {
	if (per_vrf_sessions->ses_count == 0)
	  {
	    vec_add1 (to_free, per_vrf_sessions - tsm->per_vrf_sessions_vec);
	  }
      }
  }

  if (vec_len (to_free))
    {
      vec_foreach (i, to_free)
      {
	vec_del1 (tsm->per_vrf_sessions_vec, *i);
      }
    }

  vec_free (to_free);
}

// slow path
static_always_inline void
per_vrf_sessions_register_session (snat_session_t * s, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions_t *per_vrf_sessions;

  per_vrf_sessions_cleanup (thread_index);

  // s->per_vrf_sessions_index == ~0 ... reuse of old session

  vec_foreach (per_vrf_sessions, tsm->per_vrf_sessions_vec)
  {
    // ignore already expired registrations
    if (per_vrf_sessions->expired)
      continue;

    if ((s->in2out.fib_index == per_vrf_sessions->rx_fib_index) &&
	(s->out2in.fib_index == per_vrf_sessions->tx_fib_index))
      {
	goto done;
      }
    if ((s->in2out.fib_index == per_vrf_sessions->tx_fib_index) &&
	(s->out2in.fib_index == per_vrf_sessions->rx_fib_index))
      {
	goto done;
      }
  }

  // create a new registration
  vec_add2 (tsm->per_vrf_sessions_vec, per_vrf_sessions, 1);
  clib_memset (per_vrf_sessions, 0, sizeof (*per_vrf_sessions));

  per_vrf_sessions->rx_fib_index = s->in2out.fib_index;
  per_vrf_sessions->tx_fib_index = s->out2in.fib_index;

done:
  s->per_vrf_sessions_index = per_vrf_sessions - tsm->per_vrf_sessions_vec;
  per_vrf_sessions->ses_count++;
}

// fast path
static_always_inline void
per_vrf_sessions_unregister_session (snat_session_t * s, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  per_vrf_sessions_t *per_vrf_sessions;

  ASSERT (s->per_vrf_sessions_index != ~0);
  
  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions = vec_elt_at_index (tsm->per_vrf_sessions_vec,
                                       s->per_vrf_sessions_index);

  ASSERT (per_vrf_sessions->ses_count != 0);

  per_vrf_sessions->ses_count--;
  s->per_vrf_sessions_index = ~0;
}

// fast path
static_always_inline u8
per_vrf_sessions_is_expired (snat_session_t * s, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  per_vrf_sessions_t *per_vrf_sessions;

  ASSERT (s->per_vrf_sessions_index != ~0);

  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions = vec_elt_at_index (tsm->per_vrf_sessions_vec,
                                       s->per_vrf_sessions_index);
  return per_vrf_sessions->expired;
}

#ifdef FLEXIWAN_FEATURE
/* Feature name: nat_interface_specific_address_selection */
/*
 * The function marks the snat session with the interface sw_if_index value if
 * the NAT IP address belongs to that interface
 */
static_always_inline void
nat44_ed_set_session_interface (snat_main_t * sm, snat_session_t * s,
				u32 pkt_tx_sw_if_index, u32 ip_addr_as_u32)
{
  /*
   * Process only for output-feature. In the in2out_ed, It is expected that
   * packet's tx interface (vnet_buffer (b)->sw_if_index[VLIB_TX])
   * is already set for output feature. In the input-feature case, packet's tx
   * interface value is expected to be with value ~0
   */
  if (pkt_tx_sw_if_index != ~0)
    {
      /*
       * Searches the snat address context to look for a match of both
       * sw_if_index and IP address
       */
      snat_address_t *ap;
      vec_foreach (ap, sm->addresses)
	{
	  if ((pkt_tx_sw_if_index == ap->tx_sw_if_index) &&
	      (ip_addr_as_u32 == ap->addr.as_u32))
	    {
	      s->sw_if_index = pkt_tx_sw_if_index;
	      break;
	    }
	}
    }
}

/*
 * The function deletes the snat session if the interface assigned to the
 * packet by the earlier routing decision mismatches with the interface value
 * cached in the session context. This can possibly happen if there was a
 * routing change in middle of the flow.
 *
 * This is performed to provide an opportunity for new NAT session create based
 * on route change. Changing NAT IP in middle of flow would still break
 * connection oriented transport like TCP. But can possibly help in recovering
 * applications built over connection-less UDP or ICMP.
 */
static_always_inline i32
nat44_ed_delete_session_on_intf_mismatch (snat_main_t * sm,
					  snat_session_t * s,
					  u32 pkt_tx_sw_if_index,
					  u32 thread_index)
{
  /*
   * Process only for output-feature. In the in2out_ed, It is expected that
   * packet's tx interface (vnet_buffer (b)->sw_if_index[VLIB_TX])
   * is already set for output feature. In the input-feature case, packet's tx
   * interface value is expected to be with value ~0
   */
  if (PREDICT_FALSE ((pkt_tx_sw_if_index != ~0) && (s->sw_if_index != ~0) &&
		     (pkt_tx_sw_if_index != s->sw_if_index)))
    {
      nat_free_session_data (sm, s, thread_index, 0);
      nat_ed_session_delete (sm, s, thread_index, 1);
      return 1;
    }
  return 0;
}

#endif

#ifdef FLEXIWAN_FEATURE
/* Feature name : session_recovery_on_nat_addr_flap */
/*
 * Makes below checks to decide if session is recoverable.
 * - Is session_recovery enabled on the interface
 * - Is the same NAT address back on the interface
 * If recoverable, unsets STALE_NAT_ADDR flag and increments port refcount
 * states as required
 */
static_always_inline i32
nat44_ed_recover_session (snat_session_t *s, u32 sw_if_index, u32 thread_index,
			  ip4_address_t *addr, u16 port_host_byte_order)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *ap;
  i32 recover = 0, is_session_recovery = 0;

  if (sw_if_index != ~0)
    {
      is_session_recovery = nat44_interface_is_session_recovery (sw_if_index);
    }
  if (is_session_recovery)
    {
      vec_foreach (ap, sm->addresses)
	{
	  if ((ap->addr.as_u32 == addr->as_u32) &&
	      (ap->tx_sw_if_index == sw_if_index))
	    {
	      recover = 1;
	      break;
	    }
	}
    }

  if (recover)
    {
      switch (s->nat_proto)
	{
#define _(N, j, n, s) \
	  case NAT_PROTOCOL_##N: \
	    ++ap->busy_##n##_port_refcounts[port_host_byte_order]; \
	    ap->busy_##n##_ports_per_thread[thread_index]++; \
	    ap->busy_##n##_ports++; \
	  break;
	  foreach_nat_protocol

	  default:
	    nat_elog_info ("unknown protocol");
            return VNET_API_ERROR_INVALID_VALUE;
#undef _
	}
      s->flags &= ~SNAT_SESSION_FLAG_STALE_NAT_ADDR;
    }
  else
    {
      return VNET_API_ERROR_INVALID_VALUE;
    }
  return 0;
}
#endif

#endif
