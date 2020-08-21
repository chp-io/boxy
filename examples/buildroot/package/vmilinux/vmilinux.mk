################################################################################
#
# vmilinux
#
################################################################################

VMILINUX_SITE = ${BR2_EXTERNAL_vmilinux_PATH}/../.. # ${BOXY_SOURCE_ROOT_DIR}
VMILINUX_SITE_METHOD = local
VMILINUX_OVERRIDE_SRCDIR_RSYNC_EXCLUSIONS = \
	--exclude build \
	--exclude 'build_*' \
	--exclude cache  # Prevents rsync protocol error caused by vbox fs driver

VMILINUX_LICENSE = MIT

# VMILINUX_SUBDIR = hypervisor
VMILINUX_SUPPORTS_IN_SOURCE_BUILD = NO
VMILINUX_CONF_OPTS = -DBUILD_SHARED_LIBS=NO
VMILINUX_MAKE_OPTS = vmilinux_x86_64-userspace-elf

define VMILINUX_CONFIGURE_CMDS
	(cd $(@D); \
		[[ -d buildroot-build ]] || mkdir buildroot-build; \
		cd buildroot-build; \
		$(TARGET_MAKE_ENV) cmake ../hypervisor \
			-DENABLE_BUILD_EXAMPLES=ON \
			-DREKALL_PROFILE_PATH=${REKALL_PROFILE_PATH} \
			-DVOLATILITY_PROFILE_PATH=${VOLATILITY_PROFILE_PATH} \
			-DCACHE_DIR=${CACHE_DIR} \
	)
endef

define VMILINUX_INSTALL_TARGET_CMDS
	$(INSTALL) -m 0755 \
		-D $(@D)/buildroot-build/prefixes/initrd/sbin/init-vmi \
		$(TARGET_DIR)/sbin/init
endef

$(eval $(cmake-package))