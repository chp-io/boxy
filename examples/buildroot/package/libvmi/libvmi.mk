################################################################################
#
# LibVMI
#
################################################################################

ifeq ($(BR2_LIBVMI_PATH),)
	LIBVMI_VERSION = 6e485bc592c123c9f5cf73b7d5b55dd2a70a11a3
	LIBVMI_SITE = $(call github,chp-io,libvmi,$(LIBVMI_VERSION))
	LIBVMI_REPO = https://github.com/chp-io/libvmi
else
	LIBVMI_SITE = ${BR2_LIBVMI_PATH}
	LIBVMI_SITE_METHOD = local
	LIBVMI_OVERRIDE_SRCDIR_RSYNC_EXCLUSIONS = --exclude '/deps'
endif

LIBVMI_LICENSE = LGPLv3
LIBVMI_LICENSE_FILES = COPYING

LIBVMI_DEPENDENCIES = json-c libglib2
HOST_LIBVMI_DEPENDENCIES = host-pkgconf host-bison host-flex host-libglib2
LIBVMI_CONF_OPTS = \
	-DENABLE_XENSTORE=OFF \
	-DENABLE_XEN=OFF \
	-DENABLE_FILE=OFF \
	-DENABLE_VMIFS=OFF \
	-DENABLE_KVM=OFF \
	-DBUILD_EXAMPLES=ON \
	-DENABLE_FREEBSD=OFF \
	-DENABLE_STATIC=OFF \
	-DENABLE_PAGE_CACHE=OFF

ifeq ($(BR2_LIBVMI_DEBUG),y)
	LIBVMI_CONF_OPTS += -DCMAKE_BUILD_TYPE=Debug \
						-DVMI_DEBUG=__VMI_DEBUG_ALL
else
	LIBVMI_CONF_OPTS += -DCMAKE_BUILD_TYPE=Release
endif

ifeq ($(BR2_LIBVMI_INCLUDE_EXAMPLES),y)
define LIBVMI_INSTALL_EXAMPLES
	$(INSTALL) -m 0755 -D $(@D)/examples/cr3-event-example \
		$(TARGET_DIR)/usr/bin/
	$(INSTALL) -m 0755 -D $(@D)/examples/mem-event-example \
		$(TARGET_DIR)/usr/bin/
	$(INSTALL) -m 0755 -D $(@D)/examples/singlestep-event-example \
		$(TARGET_DIR)/usr/bin/
endef
LIBVMI_POST_INSTALL_TARGET_HOOKS += LIBVMI_INSTALL_EXAMPLES
endif

$(eval $(cmake-package))
