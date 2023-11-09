#ifndef CONFIG_H_IN
#define CONFIG_H_IN

#define HAVE_STATEMENT_EXPR 1
#define HAVE_BUILTIN_TYPES_COMPATIBLE_P 1
#define HAVE_TYPEOF 1
#define HAVE_ISBLANK 1
#define HAVE_BUILTIN_CLZ 1
#define HAVE_BUILTIN_CLZL 1

#define PACKAGE_VERSION "31.1"

// FIXME: Remove this, The cmake version hard-requires new style CLOEXEC support
#define STREAM_CLOEXEC "e"

#define RDMA_CDEV_DIR "/dev/infiniband"

#define IBV_CONFIG_DIR "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/etc/libibverbs.d"
#define RS_CONF_DIR "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/etc/rdma/rsocket"
#define IWPM_CONFIG_FILE "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/etc/iwpmd.conf"

#define SRP_DAEMON_CONFIG_FILE "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/etc/srp_daemon.conf"
#define SRP_DAEMON_LOCK_PREFIX "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/var/run/srp_daemon"

#define ACM_CONF_DIR "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/etc/rdma"
#define IBACM_LIB_PATH "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/lib/ibacm"
#define IBACM_BIN_PATH "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/bin"
#define IBACM_PID_FILE "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/var/run/ibacm.pid"
#define IBACM_PORT_BASE "ibacm-tcp.port"
#define IBACM_IBACME_PORT_FILE "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/var/run/" IBACM_PORT_BASE
#define IBACM_PORT_FILE "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/var/run/ibacm.port"
#define IBACM_LOG_FILE "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/var/log/ibacm.log"
#define IBACM_SERVER_BASE "ibacm-unix.sock"
#define IBACM_IBACME_SERVER_PATH "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/var/run/" IBACM_SERVER_BASE
#define IBACM_SERVER_PATH "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/var/run/ibacm.sock"

#define IBDIAG_CONFIG_PATH "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/etc/infiniband-diags"
#define IBDIAG_NODENAME_MAP_PATH "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/etc/rdma/ib-node-name-map"

#define VERBS_PROVIDER_DIR "/home/vagrant/flexisase/Submodules/flexiroutervpp/build-root/install-vpp_debug-native/external/lib/libibverbs"
#define VERBS_PROVIDER_SUFFIX "-rdmav25.so"
#define IBVERBS_PABI_VERSION 25

// FIXME This has been supported in compilers forever, we should just fail to build on such old systems.
#define HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE 1

#define HAVE_FUNC_ATTRIBUTE_IFUNC 1

/* #undef HAVE_WORKING_IF_H */

// Operating mode for symbol versions
#define HAVE_FULL_SYMBOL_VERSIONS 1
/* #undef HAVE_LIMITED_SYMBOL_VERSIONS */

#define SIZEOF_LONG 8

#if 3 == 1
# define VERBS_IOCTL_ONLY 1
# define VERBS_WRITE_ONLY 0
#elif  3 == 2
# define VERBS_IOCTL_ONLY 0
# define VERBS_WRITE_ONLY 1
#elif  3 == 3
# define VERBS_IOCTL_ONLY 0
# define VERBS_WRITE_ONLY 0
#endif

// Configuration defaults

#define IBACM_SERVER_MODE_UNIX 0
#define IBACM_SERVER_MODE_LOOP 1
#define IBACM_SERVER_MODE_OPEN 2
#define IBACM_SERVER_MODE_DEFAULT IBACM_SERVER_MODE_UNIX

#define IBACM_ACME_PLUS_KERNEL_ONLY_DEFAULT 0

#endif
