#
# Copyright (C) 2020 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

if(ENABLE_BUILD_EXAMPLES AND ENABLE_BUILD_USERSPACE AND NOT WIN32 AND NOT CYGWIN)
    message(STATUS "Including dependency: buildroot")

    set(BUILDROOT_BUILD_DIR ${DEPENDS_DIR}/buildroot/${USERSPACE_PREFIX}/build)
    set(BUILDROOT_ENV REKALL_PROFILE_PATH=${REKALL_PROFILE_PATH} VOLATILITY_PROFILE_PATH=${VOLATILITY_PROFILE_PATH} CACHE_DIR=${CACHE_DIR})

    download_dependency(
        buildroot-source
        URL           ${BUILDROOT_URL}
        URL_MD5       ${BUILDROOT_URL_MD5}
        PATCH_COMMAND ${CMAKE_COMMAND} -E chdir "${CACHE_DIR}/buildroot-source" git apply -p1 ${BOXY_SOURCE_EXAMPLES_DIR}/buildroot/patch/0001-package-json-c-bump-version-to-0.14.patch
    )

    add_dependency(
        buildroot-source userspace
        CONFIGURE_COMMAND   ${CMAKE_COMMAND} -E echo "-- skip"
        BUILD_COMMAND       ${CMAKE_COMMAND} -E echo "-- skip"
        INSTALL_COMMAND     ${CMAKE_COMMAND} -E echo "-- skip"
        DOWNLOAD_COMMAND    ${CMAKE_COMMAND} -E echo "-- skip"
    )

    add_dependency_step(
        buildroot-source userspace
        COMMAND ${CMAKE_COMMAND} -E make_directory ${BUILDROOT_BUILD_DIR}
        COMMAND ${CMAKE_COMMAND} -DSRC=${CACHE_DIR}/buildroot-source/ -DDST=${BUILDROOT_BUILD_DIR}
                                 -P ${BOXY_SOURCE_CMAKE_DIR}/utils/copy_no_follow.cmake
        COMMAND ${CMAKE_COMMAND} -E chdir ${BUILDROOT_BUILD_DIR}
            env ${BUILDROOT_ENV}
            make BR2_EXTERNAL=${BOXY_SOURCE_EXAMPLES_DIR}/buildroot vmilinux_defconfig
        COMMAND ${CMAKE_COMMAND} -E make_directory ${PREFIXES_DIR}/vms/buildroot
    )

    add_dependency(
        buildroot userspace
        CONFIGURE_COMMAND   ${CMAKE_COMMAND} -E echo "-- skip"
        BUILD_COMMAND       ${CMAKE_COMMAND} -E echo "-- skip"
        INSTALL_COMMAND     ${CMAKE_COMMAND} -E echo "-- skip"
        DOWNLOAD_COMMAND    ${CMAKE_COMMAND} -E echo "-- skip"
        UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "-- checking for updates"
        DEPENDS             buildroot-source_${USERSPACE_PREFIX}
    )

    add_dependency_step(
        buildroot userspace
        COMMAND ${CMAKE_COMMAND} -E chdir ${BUILDROOT_BUILD_DIR}
            env ${BUILDROOT_ENV}
            make -j${BUILD_TARGET_CORES}
        COMMAND ${CMAKE_COMMAND} -E copy
            ${BUILDROOT_BUILD_DIR}/output/images/bzImage
            ${BUILDROOT_BUILD_DIR}/output/images/rootfs.cpio.gz
            ${PREFIXES_DIR}/vms/buildroot
    )

    add_dependencies(vms buildroot_${USERSPACE_PREFIX})
endif()
