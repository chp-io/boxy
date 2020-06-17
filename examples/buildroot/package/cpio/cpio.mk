################################################################################
#
# cpio to archive target filesystem
#
################################################################################

# Overrides rootfs cpio config from fs/cpio/cpio.mk
# to prevent it from placing /init

ROOTFS_CPIO_PRE_GEN_HOOKS =
