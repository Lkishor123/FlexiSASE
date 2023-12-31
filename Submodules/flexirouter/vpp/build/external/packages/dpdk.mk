# Copyright (c) 2020 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
#  - integrating_dpdk_qos_sched : The DPDK QoS scheduler integration in VPP is
#  currently in deprecated state. It is likely deprecated as changes in
#  DPDK scheduler APIs required corresponding changes from VPP side.
#  The FlexiWAN commit makes the required corresponding changes and brings back
#  the feature to working state. Additionaly made enhancements in the context
#  of WAN QoS needs.

DPDK_PKTMBUF_HEADROOM        ?= 128
DPDK_USE_LIBBSD              ?= n
#FLEXIWAN_FEATURE - integrating_dpdk_qos_sched - Start 
DPDK_SCHED_COLLECT_STATS     ?= y
DPDK_SCHED_SUBPORT_TC_OV     ?= y
DPDK_SCHED_RED               ?= y
#FLEXIWAN_FEATURE - integrating_dpdk_qos_sched - End 
DPDK_DEBUG                   ?= n
DPDK_MLX4_PMD                ?= n
DPDK_MLX5_PMD                ?= y
DPDK_MLX5_COMMON_PMD         ?= n
#FLEXIWAN_FEATURE - integrating_dpdk_qos_sched - Start 
DPDK_TAP_PMD                 ?= y
#DPDK_TAP_PMD                ?= n (By default disabled)
#FLEXIWAN_FEATURE - integrating_dpdk_qos_sched - End 
DPDK_FAILSAFE_PMD            ?= n
DPDK_MACHINE                 ?= default
DPDK_MLX_IBV_LINK            ?= static

dpdk_version                 ?= 20.11
dpdk_base_url                ?= http://fast.dpdk.org/rel
dpdk_tarball                 := dpdk-$(dpdk_version).tar.xz
dpdk_tarball_md5sum_20.11    := 13a990dc3b300635f685e268b36918a3
dpdk_tarball_md5sum          := $(dpdk_tarball_md5sum_$(dpdk_version))
dpdk_url                     := $(dpdk_base_url)/$(dpdk_tarball)
dpdk_tarball_strip_dirs      := 1
dpdk_depends		     := rdma-core $(if $(ARCH_X86_64), ipsec-mb)
# Debug or release

DPDK_BUILD_TYPE:=release
ifeq ($(DPDK_DEBUG), y)
DPDK_BUILD_TYPE:=debug
endif

#FLEXIWAN_FEATURE - integrating_dpdk_qos_sched
#Change: The af_packet driver was removed from disable list
DPDK_DRIVERS_DISABLED := baseband/\*,	\
	bus/dpaa,							\
	bus/ifpga,							\
	compress/isal,						\
	compress/octeontx,					\
	compress/zlib,						\
	crypto/ccp,							\
	crypto/dpaa_sec,					\
	crypto/openssl,						\
	crypto/aesni_mb,						\
	crypto/aesni_gcm,						\
	crypto/kasumi,						\
	crypto/snow3g,						\
	crypto/zuc,						\
	event/\*,							\
	mempool/dpaa,						\
	net/bnx2x,							\
	net/bonding,						\
	net/ipn3ke,							\
	net/liquidio,						\
	net/pcap,							\
	net/pfe,							\
	net/sfc,							\
	net/softnic,						\
	net/thunderx,						\
	raw/ifpga,							\
	net/af_xdp							

DPDK_LIBS_DISABLED := acl,				\
	bbdev,								\
	bitratestats,						\
	bpf,								\
	cfgfile,							\
	distributor,						\
	efd,								\
	fib,								\
	flow_classify,						\
	graph,								\
	gro,								\
	gso,								\
	jobstats,							\
	kni,								\
	latencystats,						\
	lpm,								\
	member,								\
	node,								\
	pipeline,							\
	port,								\
	power,								\
	rawdev,								\
	rib,								\
	table

DPDK_MLX_CONFIG_FLAG :=

# Adjust disabled pmd and libs depending on user provided variables
ifeq ($(DPDK_MLX4_PMD), n)
	DPDK_DRIVERS_DISABLED += ,net/mlx4
else
	DPDK_MLX_CONFIG_FLAG := -Dibverbs_link=${DPDK_MLX_IBV_LINK}
endif
ifeq ($(DPDK_MLX5_PMD), n)
	DPDK_DRIVERS_DISABLED += ,net/mlx5
else
	DPDK_MLX_CONFIG_FLAG := -Dibverbs_link=${DPDK_MLX_IBV_LINK}
endif
ifeq ($(DPDK_MLX5_COMMON_PMD), n)
	DPDK_DRIVERS_DISABLED += ,common/mlx5
else
	DPDK_MLX_CONFIG_FLAG := -Dibverbs_link=${DPDK_MLX_IBV_LINK}
endif
ifeq ($(DPDK_TAP_PMD), n)
	DPDK_DRIVERS_DISABLED += ,net/tap
endif
ifeq ($(DPDK_FAILSAFE_PMD), n)
	DPDK_DRIVERS_DISABLED += ,net/failsafe
endif

# Sanitize DPDK_DRIVERS_DISABLED and DPDK_LIBS_DISABLED
DPDK_DRIVERS_DISABLED := $(shell echo $(DPDK_DRIVERS_DISABLED) | tr -d '\\\t ')
DPDK_LIBS_DISABLED := $(shell echo $(DPDK_LIBS_DISABLED) | tr -d '\\\t ')

HASH := \#
# post-meson-setup snippet to alter rte_build_config.h
define dpdk_config
if grep -q RTE_$(1) $(dpdk_src_dir)/config/rte_config.h ; then	\
sed -i -e 's/$(HASH)define RTE_$(1).*/$(HASH)define RTE_$(1) $(DPDK_$(1))/' \
	$(dpdk_src_dir)/config/rte_config.h; \
elif grep -q RTE_$(1) $(dpdk_build_dir)/rte_build_config.h ; then \
sed -i -e 's/$(HASH)define RTE_$(1).*/$(HASH)define RTE_$(1) $(DPDK_$(1))/' \
	$(dpdk_build_dir)/rte_build_config.h; \
else \
echo '$(HASH)define RTE_$(1) $(DPDK_$(1))' \
	>> $(dpdk_build_dir)/rte_build_config.h ; \
fi
endef

#FLEXIWAN_FEATURE - integrating_dpdk_qos_sched
#Changes: Fixes required to add the enabled features to the config file
define dpdk_config_def
if [[ "$(DPDK_$(1))" == "y" ]]; then \
    if ! grep -q "RTE_$(1)" $(dpdk_build_dir)/rte_build_config.h ; then \
        echo '$(HASH)define RTE_$(1) 1' \
          >> $(dpdk_build_dir)/rte_build_config.h ; \
    fi; \
    sed -i "s/.*RTE_$(1).*/$(HASH)define RTE_$(1) 1/" \
           $(dpdk_src_dir)/config/rte_config.h ; \
elif [[ "$(DPDK_$(1))" == "n" ]]; then \
    sed -i '/$(HASH)define RTE_$(1) .*/d' $(dpdk_build_dir)/rte_build_config.h \
      $(dpdk_src_dir)/config/rte_config.h ; \
fi
endef

DPDK_MESON_ARGS = \
	--default-library static \
	--libdir lib \
	--prefix $(dpdk_install_dir) \
	-Dtests=false \
	"-Ddisable_drivers=$(DPDK_DRIVERS_DISABLED)" \
	"-Ddisable_libs=$(DPDK_LIBS_DISABLED)" \
	-Db_pie=true \
	-Dmachine=$(DPDK_MACHINE) \
	--buildtype=$(DPDK_BUILD_TYPE) \
	${DPDK_MLX_CONFIG_FLAG}

PIP_DOWNLOAD_DIR = $(CURDIR)/downloads/

#FLEXIWAN_FEATURE - integrating_dpdk_qos_sched
# Changes: Added calls to SCHED_COLLECT_STATS, SCHED_RED, SCHED_SUBPORT_TC_OV
define dpdk_config_cmds
	cd $(dpdk_build_dir) && \
	rm -rf ../dpdk-meson-venv && \
	mkdir -p ../dpdk-meson-venv && \
	python3 -m venv ../dpdk-meson-venv && \
	source ../dpdk-meson-venv/bin/activate && \
	(if ! ls $(PIP_DOWNLOAD_DIR)meson* ; then pip3 download -d $(PIP_DOWNLOAD_DIR) -f $(DL_CACHE_DIR) meson==0.54 setuptools wheel; fi) && \
	pip3 install --no-index --find-links=$(PIP_DOWNLOAD_DIR) meson==0.54 && \
	PKG_CONFIG_PATH=$(dpdk_install_dir)/lib/pkgconfig meson setup $(dpdk_src_dir) \
		$(dpdk_build_dir) \
		$(DPDK_MESON_ARGS) \
			| tee $(dpdk_config_log) && \
	deactivate && \
	echo "DPDK post meson configuration" && \
	echo "Altering rte_build_config.h" && \
	$(call dpdk_config,PKTMBUF_HEADROOM) && \
	$(call dpdk_config_def,SCHED_COLLECT_STATS) && \
	$(call dpdk_config_def,SCHED_RED) && \
	$(call dpdk_config_def,SCHED_SUBPORT_TC_OV) && \
	$(call dpdk_config_def,USE_LIBBSD)
endef

define dpdk_build_cmds
	cd $(dpdk_build_dir) && \
	source ../dpdk-meson-venv/bin/activate && \
	meson compile -C . | tee $(dpdk_build_log) && \
	deactivate
endef

define dpdk_install_cmds
	cd $(dpdk_build_dir) && \
	source ../dpdk-meson-venv/bin/activate && \
	meson install && \
	cd $(dpdk_install_dir)/lib && \
	echo "GROUP ( $$(ls librte*.a ) )" > libdpdk.a && \
	rm -rf librte*.so librte*.so.* dpdk/*/librte*.so dpdk/*/librte*.so.* && \
	deactivate
endef

$(eval $(call package,dpdk))
