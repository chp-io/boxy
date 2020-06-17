################################################################################
#
# LibVMI
#
################################################################################

LIBVMI_VERSION = 1dd5a2e48e43b70b50d7ff4a01ad1fcb3b8cbba7
LIBVMI_SITE = $(call github,chp-io,libvmi,$(LIBVMI_VERSION))
LIBVMI_REPO = https://github.com/chp-io/libvmi

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
	-DENABLE_ADDRESS_CACHE=OFF \
	-DENABLE_PAGE_CACHE=OFF \
	-DCMAKE_BUILD_TYPE=DEBUG
	# -DVMI_DEBUG=__VMI_DEBUG_ALL

$(eval $(cmake-package))