/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *  Copyright (C) 2020 flexiWAN Ltd.
 *  This file is part of the FWABF plugin.
 *  The FWABF plugin is fork of the FDIO VPP ABF plugin.
 *  It enhances ABF with functionality required for Flexiwan Multi-Link feature.
 *  For more details see official documentation on the Flexiwan Multi-Link.
 */

/*
 * This file implements database of FWABF Links.
 * The FWABF Link object is abstraction of interface, either FlexiWAN tunnel
 * interface or WAN interface in case of Direct Internet Access, that holds data
 * needed for the FlexiWAN multi-link policy feature, e.g. labels, DPO-s, etc.
 * Actually Link is a structure that extends the VPP software interface object.
 * It just keeps all FlexiWAN related logic separated of core VPP code.
 *
 * The main API function of this file is fwabf_links_get_intersected_dpo().
 * Once the FWABF Link database is filled with interfaces, labels, etc,
 * this API can be used to retrieve DPO object by FWABF label.
 * This DPO object then is used for forwarding packet to the labeled tunnel/WAN
 * interface.
 */

#ifndef __FWABF_LINKS_H__
#define __FWABF_LINKS_H__

#include <vnet/fib/fib_path_list.h>


typedef u8 fwabf_label_t;	/*flexiwan path label used by policy to choose link*/

#define FWABF_INVALID_LABEL 0xFF
#define FWABF_MAX_LABEL     0xFE

/*
   The following structures defines traffic quality characteristics
   as per RFC 4594 Configuration Guidelines for DiffServ Service Classes
*/

typedef struct fwabf_quality_t_ {
    u32 loss;
    u32 delay;
    u32 jitter;
} fwabf_quality_t;

/* Service Classes as per RFC 4594 Figure 2 */
typedef enum fwabf_quality_service_class_t_ {
    FWABF_QUALITY_SC_MIN                       = -1,
    FWABF_QUALITY_SC_TELEPHONY                 = 0,
    FWABF_QUALITY_SC_BROADCAST_VIDEO           = 1,
    FWABF_QUALITY_SC_REAL_TIME                 = 2,
    FWABF_QUALITY_SC_SIGNALING                 = 3,
    FWABF_QUALITY_SC_NETWORK_CONTROL           = 4,
    FWABF_QUALITY_SC_LOW_LATENCY               = 5,
    FWABF_QUALITY_SC_OAM                       = 6,
    FWABF_QUALITY_SC_HIGH_THROUGHPUT           = 7,
    FWABF_QUALITY_SC_MULTIMEDIA_CONFERENCING   = 8,
    FWABF_QUALITY_SC_MULTIMEDIA_STREAMING      = 9,
    FWABF_QUALITY_SC_STANDARD                  = 10,
    /* keep this last! */
    FWABF_QUALITY_SC_MAX
} fwabf_quality_service_class_t;

typedef enum fwabf_quality_level_t_ {
    FWABF_QUALITY_LEVEL_VERY_LOW,
    FWABF_QUALITY_LEVEL_LOW,
    FWABF_QUALITY_LEVEL_LOW_MEDIUM,
    FWABF_QUALITY_LEVEL_MEDIUM,
    FWABF_QUALITY_LEVEL_MEDIUM_HIGH,
    FWABF_QUALITY_LEVEL_HIGH,
    FWABF_QUALITY_LEVEL_YES
} fwabf_quality_level_t;

/**
 * Creates FWABF Link object that holds interface <-> label mapping and other
 * data needed for FWABF Policy feature. See fwabf_link_t for details.
 *
 * @param sw_if_index   index of VPP software interface used by tunnel or by WAN interface.
 * @param fwlabel       FWABF label for that tunnel/WAN interface.
 * @param rpath         the remote end of tunnel / gateway of WAN interface.
 *                      It is needed to track reachability of tunnel remote end/gateway.
 * @return 1 on success, 0 otherwise.
 */
extern u32 fwabf_links_add_interface (
                        const u32               sw_if_index,
                        const fwabf_label_t     fwlabel,
                        const fib_route_path_t* rpath);

/**
 * Delets FWABF Link object.
 *
 * @param sw_if_index   index of VPP software interface associated with Link.
 * @return 1 on success, 0 otherwise.
 */
extern u32 fwabf_links_del_interface (const u32 sw_if_index);

/**
 * Verifies if link satisfies quality requirements according
 * to packet Service Class demands matched by ACL tag
 *
 * @param fwlabel      the label to be used to find labeled tunnel DPO-s
 * @param sc           traffic service class from ACL matched by packet
 * @param reduce_level if there is no available links which satisfy criteria for service class requirements
 *                     we reduce requirements to the next level and check again
 * @return 1 if link quality requirements are satisfied, 0 otherwise.
 */
extern dpo_id_t fwabf_links_get_quality_dpo (
                        fwabf_label_t*                  policy_labels,
                        fwabf_quality_service_class_t   sc,
                        const load_balance_t*           lb,
                        u32                             is_default_route_lb,
                        u32                             flow_hash);

/**
 * Intersects DPO-s retrieved by FIB lookup with DPO-s that belong to labeled
 * tunnels. Only reachable tunnels are considered.
 * If FIB lookup returned a number of DPO-s - Equal Cost Multi Path case -
 * the first of them which is successfully intersected will be returned.
 *
 * @param fwlabel   the label to be used to find labeled tunnel DPO-s
 * @param lb        the result of FIB lookup. It is DPO of Load Balance type.
 *                  It can't be used for forwarding. It is used to hold one or
 *                  more children DPO-s that can be used for forwarding.
 * @param proto     IPv4/IPv6
 * @return DPO to be used for forwarding or DPO_INVALID if intersection failed.
 */
extern dpo_id_t fwabf_links_get_intersected_dpo (
                        fwabf_label_t         fwlabel,
                        const load_balance_t* lb,
                        dpo_proto_t           proto);

/**
 * Retrieves DPO of the WAN/tunnel interface labeled with 'fwlabel'.
 *
 * @param fwlabel   the label of the WAN/tunnel.
 * @return DPO to be used for forwarding or DPO_INVALID if labeled WAN/tunnel is down.
 */
extern dpo_id_t fwabf_links_get_labeled_dpo (
                        fwabf_label_t         fwlabel);

/**
 * Checks if DPO-s retrieved by FIB lookup belong to labeled tunnels, labeled
 * DIA interfaces or default route interface. This is either reachable currently
 * or unreachable.
 * Note we check the first of FIB lookup DPO-s only, as there is enforcement
 * on user behavior: if user wants policy, he has to label all tunnels/WAN-s.
 *
 * @param lb        the result of FIB lookup. It is DPO of Load Balance type.
 *                  It can't be used for forwarding. It is used to hold one or
 *                  more children DPO-s that can be used for forwarding.
 * @param proto     DPO_PROTO_IP4/DPO_PROTO_IP6.
 * @return 1 if DPO is labeled or belongs to default route, 0 otherwise.
 */
extern int fwabf_links_is_dpo_labeled_or_default_route (
                            const load_balance_t* lb,
                            dpo_proto_t           proto);

/**
 * Checks if DPO-s retrieved by FIB lookup belong to default route interface.
 *
 * @param lb        the result of FIB lookup. It is DPO of Load Balance type.
 *                  It can't be used for forwarding. It is used to hold one or
 *                  more children DPO-s that can be used for forwarding.
 * @param proto     DPO_PROTO_IP4/DPO_PROTO_IP6.
 * @return 1 if DPO belongs to default route, 0 otherwise.
 */
extern int fwabf_links_is_dpo_default_route (
                            const load_balance_t* lb,
                            dpo_proto_t           proto);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /*__FWABF_LINKS_H__*/
