/*
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
 */

/*
 *  Copyright (C) 2021 FlexiWAN Ltd.
 *  List of fixes made for FlexiWAN (denoted by FLEXIWAN_FIX flag):
 *   - add error callback function to handle error conditions on netlink socket
 *      1. close/open netlink socket on error condition
 *   - increase size of netlink socket rx buffer to allow process more events from kernel under heavy load
 */

#define _GNU_SOURCE
#include <sched.h>

#include <librtnl/rtnl.h>
#include <librtnl/netns.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/error.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <float.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

#undef DBL_MAX
#define DBL_MAX 1000000000.0

typedef enum {
  RTNL_E_OPEN,
  RTNL_E_CLOSE,
  RTNL_E_READ,
} rtnl_event_t;

typedef enum {
  RTNL_S_INIT,
  RTNL_S_SYNC,
  RTNL_S_READY,
} rtnl_state_t;

typedef enum {
  RTNL_SS_OPENING,
  RTNL_SS_LINK,
  RTNL_SS_ADDR,
  RTNL_SS_ROUTE4,
  RTNL_SS_ROUTE6,
  RTNL_SS_NEIGH,
} rtnl_sync_state_t;

typedef struct {
  rtnl_stream_t stream;
  rtnl_state_t state;
  rtnl_sync_state_t sync_state;
  int ns_fd;
  int rtnl_socket;
  u32 unix_index;
  u32 rtnl_seq;
  f64 timeout;
} rtnl_ns_t;

typedef struct {
  f64 now;
  rtnl_ns_t *streams;
} rtnl_main_t;

static rtnl_main_t rtnl_main;
static vlib_node_registration_t rtnl_process_node;

#define RTNL_BUFFSIZ 16384
#define RTNL_DUMP_TIMEOUT 1

static inline u32 grpmask(u32 g)
{
  ASSERT (g <= 31);
  if (g) {
    return 1 << (g - 1);
  } else
    return 0;
}


u8 *format_rtnl_nsname2path(u8 *s, va_list *args)
{
  char *nsname = va_arg(*args, char *);
  if (!nsname || !strlen(nsname)) {
    return format(s, "/proc/self/ns/net");
  } else if (strpbrk(nsname, "/") != NULL) {
    return format(s, "%s", nsname);
  } else {
    return format(s, "/var/run/netns/%s", nsname);
  }
}

u8* format_rtnl_msg_type(u8 *s, va_list *args)
{
  struct nlmsghdr *hdr = va_arg(*args, struct nlmsghdr *);
  switch (hdr->nlmsg_type) {
  case RTM_NEWROUTE:
    s = format(s, "RTM_NEWROUTE");
    break;
  case RTM_DELROUTE:
    s = format(s, "RTM_DELROUTE");
    break;
  case RTM_NEWLINK:
    s = format(s, "RTM_NEWLINK");
    break;
  case RTM_DELLINK:
    s = format(s, "RTM_DELLINK");
    break;
  case RTM_NEWADDR:
    s = format(s, "RTM_NEWADDR");
    break;
  case RTM_DELADDR:
    s = format(s, "RTM_DELADDR");
    break;
  case RTM_NEWNEIGH:
    s = format(s, "RTM_NEWNEIGH");
    break;
  case RTM_DELNEIGH:
    s = format(s, "RTM_DELNEIGH");
    break;
  default:
    s = format(s, "RTM_DELNEIGH");
  }
  return s;
}

static
u8 *format_rt_flags(u8 *s, va_list *args) {
  unsigned rtm_flags = va_arg(*args, unsigned);
  if (rtm_flags & RTM_F_NOTIFY)
    s = format(s, "NOTIFY ");
  if (rtm_flags & RTM_F_CLONED)
    s = format(s, "RTM_F_CLONED ");
  if (rtm_flags & RTM_F_EQUALIZE)
    s = format(s, "RTM_F_EQUALIZE ");
  if (rtm_flags & RTM_F_PREFIX)
    s = format(s, "RTM_F_PREFIX ");
  if (rtm_flags & RTM_F_LOOKUP_TABLE)
    s = format(s, "RTM_F_LOOKUP_TABLE ");
  if (rtm_flags & RTM_F_FIB_MATCH)
    s = format(s, "RTM_F_FIB_MATCH ");
  return s;
}

u8 *format_rtmsg(u8 *s, va_list *args)
{
  struct nlmsghdr*  hdr    = va_arg(*args, struct nlmsghdr *);
  struct rtmsg*     rtm    = NLMSG_DATA(hdr);
  size_t            datalen;
  u8*               s_protocol;
  uword             family;
  int               ret;
  ns_route_t        route;

  datalen = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(*hdr));
  if(datalen < sizeof(*rtm)) {
    s = format(s, "!!! corrupted NetLink MSG !!!: hdr->nlmsg_len=%d less than (sizeof(nlmsghdr)=%d + sizeof(struct rtmsg)=%d",
          hdr->nlmsg_len, sizeof(*hdr), sizeof(struct rtmsg));
    return s;
  }


  switch (rtm->rtm_protocol)
  {
    case RTPROT_UNSPEC:   s_protocol = (u8*)"RTPROT_UNSPEC";   break;
    case RTPROT_REDIRECT: s_protocol = (u8*)"RTPROT_REDIRECT"; break;
    case RTPROT_KERNEL:   s_protocol = (u8*)"RTPROT_KERNEL";   break;
    case RTPROT_BOOT:     s_protocol = (u8*)"RTPROT_BOOT";     break;
    case RTPROT_STATIC:   s_protocol = (u8*)"RTPROT_STATIC";   break;
    case RTPROT_DHCP:     s_protocol = (u8*)"RTPROT_DHCP";     break;
    default:
      s_protocol = (u8*)"not-supported";
  }

  family = (int)rtm->rtm_family;

  s = format(s, "rtmsg: family=%U, dst_len=%d, src_len=%d, tos=%u, table=%d, protocol=%s, scope=%d, type=%d, flags=%U",
          format_address_family, family, rtm->rtm_dst_len, rtm->rtm_src_len, rtm->rtm_tos, rtm->rtm_table,
          s_protocol, rtm->rtm_scope, rtm->rtm_type, format_rt_flags, rtm->rtm_flags);
  if (datalen <= NLMSG_ALIGN(sizeof(*rtm)))
    return s;

  ret = rtnl_msg_to_ns_route(hdr, &route);
  if (ret) {
      s = format(s, "!!! failed to parse attributes !!!: %d\n", ret);
      return s;
  }
  s = format(s, " rtattrs: %U", format_ns_route, &route);
  return s;
}

u8 *format_rtnl_msg(u8 *s, va_list *args)
{
  struct nlmsghdr*  hdr = va_arg(*args, struct nlmsghdr *);

  s = format(s, "nlmsghdr: len=%d, type=%u, flags=%x, seq=%u, pid=%u ",
          hdr->nlmsg_len, hdr->nlmsg_type, hdr->nlmsg_flags, hdr->nlmsg_seq, hdr->nlmsg_pid);

  switch (hdr->nlmsg_type)
  {
      case RTM_NEWROUTE:
      case RTM_DELROUTE:
        s = format(s, "nlmsg: %U: %U", format_rtnl_msg_type, hdr, format_rtmsg, hdr);
        break;
      default:
        break;
  }
  return s;
}

static_always_inline void
rtnl_schedule_timeout(rtnl_ns_t *ns, f64 when)
{
  ns->timeout = when;
}

static_always_inline void
rtnl_cancel_timeout(rtnl_ns_t *ns)
{
  ns->timeout = DBL_MAX;
}

static clib_error_t *rtnl_read_cb(struct clib_file * f)
{
  rtnl_main_t *rm = &rtnl_main;
  vlib_main_t *vm = vlib_get_main();
  rtnl_ns_t *ns = &rm->streams[f->private_data];
  vlib_process_signal_event(vm, rtnl_process_node.index, RTNL_E_READ, (uword)(ns - rm->streams));
  return 0;
}

#ifdef FLEXIWAN_FIX
static void rtnl_sync_reset(rtnl_ns_t *ns);
static void rtnl_sync_timeout(rtnl_ns_t *ns);

static clib_error_t *rtnl_error_cb(struct clib_file * f)
{
  rtnl_main_t *rm = &rtnl_main;
  rtnl_ns_t *ns = &rm->streams[f->private_data];
  int       error = 0;
  socklen_t errlen = sizeof(error);

  if (getsockopt(ns->rtnl_socket, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen) != 0) {
    clib_warning("rtnetlink: get socket option failed, error: %s", strerror(errno));
  } else {
    clib_warning("rtnetlink: read error fd (%d) stream [%s]: %s", ns->rtnl_socket, ns->stream.name, strerror(error));
  }

  rtnl_sync_reset(ns);
  rtnl_schedule_timeout(ns, rm->now);
  rtnl_sync_timeout(ns);

  return 0;
}
#endif /* FLEXIWAN_FIX */

int rtnl_dump_request(rtnl_ns_t *ns, int type, void *req, size_t len)
{
  struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
  struct nlmsghdr nlh = {
    .nlmsg_len = NLMSG_LENGTH(len),
    .nlmsg_type = type,
    .nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST,
    .nlmsg_pid = 0,
    .nlmsg_seq = ++ns->rtnl_seq,
  };
  struct iovec iov[2] = {
    { .iov_base = &nlh, .iov_len = sizeof(nlh) },
    { .iov_base = req, .iov_len = len }
  };
  struct msghdr msg = {
    .msg_name = &nladdr,
    .msg_namelen =  sizeof(nladdr),
    .msg_iov = iov,
    .msg_iovlen = 2,
  };
  if(sendmsg(ns->rtnl_socket, &msg, 0) < 0) {
    clib_warning("sendmsg error: %s", strerror(errno));
    return -1;
  }
  return 0;
}

static void rtnl_socket_close(rtnl_ns_t *ns)
{
  clib_file_del(&file_main, &file_main.file_pool[ns->unix_index]);
  close(ns->rtnl_socket);
}

struct rtnl_thread_exec {
  int fd;
  void *(*fn)(void *);
  void *arg;
  void **ret;
};

static void *rtnl_exec_in_thread_fn(void *p)
{
  struct rtnl_thread_exec *ex = (struct rtnl_thread_exec *) p;
  if (setns(ex->fd, 0))
    return (void *) ((uword) (-errno));

  *ex->ret = ex->fn(ex->arg);
  return NULL;
}

static int rtnl_exec_in_namespace_byfd(int fd, void *(*fn)(void *), void *arg, void **ret)
{
  pthread_t thread;
  void *thread_ret;
  struct rtnl_thread_exec ex = {
    .fd = fd,
    .fn = fn,
    .arg = arg,
    .ret = ret
  };
  if(pthread_create(&thread, NULL, rtnl_exec_in_thread_fn, &ex))
    return -errno;

  if(pthread_join(thread, &thread_ret))
    return -errno;

  if (thread_ret)
    return (int) ((uword)thread_ret);

  return 0;
}

int rtnl_exec_in_namespace(u32 stream_index, void *(*fn)(void *), void *arg, void **ret)
{
  rtnl_main_t *rm = &rtnl_main;
  if (pool_is_free_index(rm->streams, stream_index))
    return -EBADR;

  rtnl_ns_t *ns = pool_elt_at_index(rm->streams, stream_index);
  return rtnl_exec_in_namespace_byfd(ns->ns_fd, fn, arg, ret);
}

int rtnl_exec_in_namespace_by_name(char *nsname, void *(*fn)(void *), void *arg, void **ret)
{
  int fd;
  u8 *s = format((u8 *)0, "%U", format_rtnl_nsname2path, nsname);

  if ((fd = open((char *)s, O_RDONLY)) < 0) {
    vec_free(s);
    return -errno;
  }

  int r = rtnl_exec_in_namespace_byfd(fd, fn, arg, ret);
  vec_free(s);
  close(fd);
  return r;
}

/* this function is run by the second thread */
static void *rtnl_thread_fn(void *p)
{
  rtnl_ns_t *ns = (rtnl_ns_t *) p;
  if (setns(ns->ns_fd, 0)) {
    clib_warning("setns(%d, %d) error %d", ns->ns_fd, CLONE_NEWNET, errno);
    return (void *) -1;
  }

  if ((ns->rtnl_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) {
    clib_warning("Cannot open socket");
    return (void *) -2;
  }

#ifdef FLEXIWAN_FIX
  {
    int size = 1024000; /* Linux double the buffer size so the final size would be 2048000 (2Mb) */
    if(setsockopt(ns->rtnl_socket, SOL_SOCKET, SO_RCVBUF, (const void *)&size, sizeof(size)) != 0) {
        clib_warning("rtnetlink: setsockopt error %s", strerror(errno));
    }
  }
#endif /* FLEXIWAN_FIX */

  return NULL;
}

static int rtnl_socket_open(rtnl_ns_t *ns)
{
  rtnl_main_t *rm = &rtnl_main;
  pthread_t thread;
  void *thread_ret;
  if(pthread_create(&thread, NULL, rtnl_thread_fn, ns)) {
    clib_warning("Can't create opening thread");
    return -1;
  }

  if(pthread_join(thread, &thread_ret)) {
    clib_warning("Can't join opening thread");
    return -2;
  }

  if (thread_ret) {
    clib_warning("Could not open netlink socket");
    return -3;
  }

  struct sockaddr_nl addr = {
    .nl_family = AF_NETLINK,
    .nl_pad = 0,
    .nl_pid = 0,
    /*add mpls message group*/
    .nl_groups = grpmask(RTNLGRP_LINK)| grpmask(RTNLGRP_IPV6_IFADDR) |
    grpmask(RTNLGRP_IPV4_IFADDR) | grpmask(RTNLGRP_IPV4_ROUTE) |
    grpmask(RTNLGRP_IPV6_ROUTE) | grpmask(RTNLGRP_NEIGH) |
    grpmask(RTNLGRP_NOTIFY) | grpmask(RTNLGRP_MPLS_ROUTE),
  };

  if (bind(ns->rtnl_socket, (struct sockaddr*) &addr, sizeof(addr))) {
    close(ns->rtnl_socket);
    return -3;
  }

  clib_file_t template = {0};
  template.read_function = rtnl_read_cb;
#ifdef FLEXIWAN_FIX
  template.error_function = rtnl_error_cb;
  template.description = format (0, "rtnetlink sock conn fd: %d", ns->rtnl_socket);
#endif /* FLEXIWAN_FIX */
  template.file_descriptor = ns->rtnl_socket;
  template.private_data = (uword) (ns - rm->streams);
  ns->unix_index = clib_file_add (&file_main, &template);
  return 0;
}

static int
rtnl_rcv_error(rtnl_ns_t *ns, struct nlmsghdr *hdr, int *error)
{
  struct nlmsgerr *err = NLMSG_DATA(hdr);
  size_t datalen = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(*hdr));
  if(datalen < sizeof(*err))
    return -1;

  *error = err->error;
  return 0;
}

static void
rtnl_sync_reset(rtnl_ns_t *ns)
{
  if (ns->sync_state == RTNL_SS_OPENING)
    return;

  rtnl_socket_close(ns);
  ns->sync_state = RTNL_SS_OPENING;
}

static void
rtnl_sync_done(rtnl_ns_t *ns)
{
  rtnl_main_t *rm = &rtnl_main;
  struct ifaddrmsg addrmsg;
  struct rtmsg rtmsg;
  struct ndmsg ndmsg;
  switch (ns->sync_state) {
  case RTNL_SS_OPENING:
    //Cannot happen here
    break;
  case RTNL_SS_LINK:
    memset(&addrmsg, 0, sizeof(addrmsg));
    addrmsg.ifa_family = AF_UNSPEC;
    if(rtnl_dump_request(ns, RTM_GETADDR, &addrmsg, sizeof(addrmsg))) {
      rtnl_sync_reset(ns);
      rtnl_schedule_timeout(ns, rm->now + 1);
      return;
    }
    rtnl_schedule_timeout(ns, rm->now + RTNL_DUMP_TIMEOUT);
    ns->sync_state = RTNL_SS_ADDR;
    break;
  case RTNL_SS_ADDR:
  case RTNL_SS_ROUTE4:
    memset(&rtmsg, 0, sizeof(rtmsg));
    rtmsg.rtm_family = (ns->sync_state == RTNL_SS_ADDR)?AF_INET:AF_INET6;
    rtmsg.rtm_table = RT_TABLE_UNSPEC;
    if(rtnl_dump_request(ns, RTM_GETROUTE, &rtmsg, sizeof(rtmsg))) {
      rtnl_sync_reset(ns);
      rtnl_schedule_timeout(ns, rm->now + 1);
      return;
    }
    rtnl_schedule_timeout(ns, rm->now + RTNL_DUMP_TIMEOUT);
    ns->sync_state = (ns->sync_state == RTNL_SS_ADDR)?RTNL_SS_ROUTE4:RTNL_SS_ROUTE6;
    break;
  case RTNL_SS_ROUTE6:
    memset(&ndmsg, 0, sizeof(ndmsg));
    ndmsg.ndm_family = AF_UNSPEC;
    if(rtnl_dump_request(ns, RTM_GETNEIGH, &ndmsg, sizeof(ndmsg))) {
      rtnl_sync_reset(ns);
      rtnl_schedule_timeout(ns, rm->now + 1);
      return;
    }
    rtnl_schedule_timeout(ns, rm->now + RTNL_DUMP_TIMEOUT);
    ns->sync_state = RTNL_SS_NEIGH;
    break;
  case RTNL_SS_NEIGH:
    ns->state = RTNL_S_READY;
    ns->sync_state = 0;
    rtnl_cancel_timeout(ns);
    break;
  }
}

static void
rtnl_sync_timeout(rtnl_ns_t *ns)
{
  rtnl_main_t *rm = &rtnl_main;
  struct ifinfomsg imsg = {};
  switch (ns->sync_state) {
  case RTNL_SS_OPENING:
    if (rtnl_socket_open(ns)) {
      rtnl_schedule_timeout(ns, rm->now + 10);
      return;
    }
    imsg.ifi_family = AF_UNSPEC;
    if (rtnl_dump_request(ns, RTM_GETLINK, &imsg, sizeof(imsg))) {
      rtnl_sync_reset(ns);
      rtnl_schedule_timeout(ns, rm->now + 10);
    }
    ns->sync_state = RTNL_SS_LINK;
    rtnl_schedule_timeout(ns, rm->now + 2);
    break;
  case RTNL_SS_LINK:
  case RTNL_SS_ADDR:
  case RTNL_SS_ROUTE4:
  case RTNL_SS_ROUTE6:
  case RTNL_SS_NEIGH:
    //Timeout happened while synchronizing
    rtnl_sync_reset(ns);
    rtnl_schedule_timeout(ns, rm->now + 1);
    break;
  }
}

static int
rtnl_ns_recv(rtnl_ns_t *ns, struct nlmsghdr *hdr)
{
  rtnl_main_t *rm = &rtnl_main;
  int ret, error = 0;

  if (ns->state == RTNL_S_SYNC &&
      ((hdr->nlmsg_flags & RTM_F_NOTIFY) ||
       (hdr->nlmsg_seq != (ns->rtnl_seq)))) {
    clib_warning("Received notification while in sync. Restart synchronization.");
    rtnl_sync_reset(ns);
    rtnl_schedule_timeout(ns, rm->now);
  }

  switch (hdr->nlmsg_type) {
  case NLMSG_DONE:
    rtnl_sync_done(ns);
    break;
  case NLMSG_ERROR:
    if((ret = rtnl_rcv_error(ns, hdr, &error)))
      return ret;
    break;
  case RTM_NEWROUTE:
  case RTM_DELROUTE:
  case RTM_NEWLINK:
  case RTM_DELLINK:
  case RTM_NEWADDR:
  case RTM_DELADDR:
  case RTM_NEWNEIGH:
  case RTM_DELNEIGH:
    if (ns->stream.recv_message)
      ns->stream.recv_message(hdr, ns->stream.opaque);
    break;
  default:
    clib_warning("Unknown rtnetlink type %d", hdr->nlmsg_type);
    break;
  }
  return 0;
}

static void
rtnl_process_open(rtnl_ns_t *ns)
{
  rtnl_main_t *rm = &rtnl_main;
  if (ns->state != RTNL_S_INIT)
    return;

  ns->state = RTNL_S_SYNC;
  ns->sync_state = RTNL_SS_OPENING;
  rtnl_schedule_timeout(ns, rm->now);
}

static void
rtnl_process_close(rtnl_ns_t *ns)
{
  rtnl_main_t *rm = &rtnl_main;
  if (ns->state == RTNL_S_INIT)
    return;

  rtnl_socket_close(ns);
  close(ns->ns_fd);
  pool_put(rm->streams, ns);
}

static int
rtnl_process_read(rtnl_ns_t *ns)
{
  uint8_t buff[RTNL_BUFFSIZ];
  ssize_t len;
  struct nlmsghdr *hdr;
  while(1) {
    if((len = recv(ns->rtnl_socket, buff, RTNL_BUFFSIZ, MSG_DONTWAIT)) < 0) {
      if(errno != EAGAIN) {
        clib_warning("rtnetlink recv error (%d) [%s]: %s", ns->rtnl_socket, ns->stream.name, strerror(errno));
        return -1;
      }
      return 0;
    }

    for(hdr = (struct nlmsghdr *) buff;
        len > 0;
        len -= NLMSG_ALIGN(hdr->nlmsg_len),
          hdr = (struct nlmsghdr *) (((uint8_t *) hdr) + NLMSG_ALIGN(hdr->nlmsg_len))) {
      if((sizeof(*hdr) > (size_t)len) || (hdr->nlmsg_len > (size_t)len)) {
        clib_warning("rtnetlink buffer too small (%d Vs %d)", (int) hdr->nlmsg_len, (int) len);
        return -1;
      }
      if (rtnl_ns_recv(ns, hdr))
        return -1;
    }
  }
  return 0;
}

static void
rtnl_process_timeout(rtnl_ns_t *ns)
{
  switch (ns->state) {
  case RTNL_S_SYNC:
    rtnl_sync_timeout(ns);
    break;
  case RTNL_S_INIT:
  case RTNL_S_READY:
    clib_warning("Should not happen");
    break;
  }
}

static uword
rtnl_process (vlib_main_t * vm,
              vlib_node_runtime_t * node,
              vlib_frame_t * frame)
{
  rtnl_main_t *rm = &rtnl_main;
  uword event_type;
  uword *event_data = 0;
  rm->now = vlib_time_now(vm);
  f64 timeout = DBL_MAX;
  rtnl_ns_t *ns;

  //Setting up
  while (1) {
    vlib_process_wait_for_event_or_clock(vm, timeout - rm->now);
    event_type = vlib_process_get_events(vm, &event_data);
    rm->now = vlib_time_now(vm);

    if (event_type == ~0) { //Clock event or no event
      pool_foreach(ns, rm->streams) {
          if (ns->timeout < rm->now) {
            ns->timeout = DBL_MAX;
            rtnl_process_timeout(ns);
          }
        };
    } else {
      rtnl_ns_t *ns;
      uword *d;
      vec_foreach(d, event_data) {
        ns = &rm->streams[d[0]];
        switch (event_type)
          {
          case RTNL_E_CLOSE:
            rtnl_process_close(ns);
            break;
          case RTNL_E_OPEN:
            rtnl_process_open(ns);
            break;
          case RTNL_E_READ:
            rtnl_process_read(ns);
            break;
          }
      }
    }

    vec_reset_length (event_data);

    timeout = DBL_MAX;
    pool_foreach(ns, rm->streams) {
        if (ns->timeout < timeout)
          timeout = ns->timeout;
      };
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(rtnl_process_node, static) = {
  .function = rtnl_process,
  .name = "rtnl-process",
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 17
};

u32
rtnl_stream_open(rtnl_stream_t *template)
{
  vlib_main_t *vm = vlib_get_main();
  rtnl_main_t *rm = &rtnl_main;
  rtnl_ns_t *ns;
  int fd;
  u8 *s = format((u8 *)0, "%U", format_rtnl_nsname2path, template->name);
  vec_add1(s, 0);

  if ((fd = open((char *)s, O_RDONLY)) < 0) {
    clib_unix_warning("open stream %s: ", s);
    vec_free(s);
    return ~0;
  }

  vec_free(s);
  pool_get(rm->streams, ns);
  ns->state = RTNL_S_INIT;
  ns->ns_fd = fd;
  ns->stream = *template;
  vlib_process_signal_event(vm, rtnl_process_node.index, RTNL_E_OPEN, (uword)(ns - rm->streams));
  return ns - rm->streams;
}

void
rtnl_stream_close(u32 stream_index)
{
  vlib_main_t *vm = vlib_get_main();
  rtnl_main_t *rm = &rtnl_main;
  ASSERT(!pool_is_free_index(rm->streams, stream_index));
  vlib_process_signal_event(vm, rtnl_process_node.index, RTNL_E_CLOSE, stream_index);
}

clib_error_t *
rtnl_init (vlib_main_t * vm)
{
  rtnl_main_t *rm = &rtnl_main;
  rm->streams = 0;
  return 0;
}

VLIB_INIT_FUNCTION (rtnl_init);
