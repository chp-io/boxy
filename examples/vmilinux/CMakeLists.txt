#
# Copyright (C) 2019 Assured Information Security, Inc.
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

cmake_minimum_required(VERSION 3.13)
project(vmilinux C CXX)

init_project(vmilinux INTERFACE)

target_link_libraries(vmilinux INTERFACE userspace::bflinux)

if (${SVMI_STATIC_INIT})
    add_executable(init-vmi
        ${CMAKE_CURRENT_LIST_DIR}/tests/test-init.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/init-vmi.cpp
    )
    target_compile_definitions(init-vmi PUBLIC
        SVMI_STATIC_INIT
        SVMI_INIT_NO_PROC_MOUNT
        SVMI_INIT_NO_PRINTK
        SVMI_CMDLINE_PATH="${CMAKE_CURRENT_LIST_DIR}/tests/cmdline.txt"
    )
    set(INIT_VMI_BIN init-vmi)
else()
    add_executable(init-vmi ${CMAKE_CURRENT_LIST_DIR}/src/init-vmi.cpp)
    set(INIT_VMI_BIN init-vmi)
endif()
target_link_options(init-vmi PRIVATE -static)
set_target_properties(init-vmi PROPERTIES CXX_STANDARD 20)
target_include_directories(init-vmi PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
    $<BUILD_INTERFACE:${BOXY_SOURCE_BFEXEC_DIR}/include>
)
target_link_libraries(${INIT_VMI_BIN} PUBLIC vmilinux)

add_custom_target(
    package ALL
    COMMAND ${CMAKE_COMMAND} -E copy ${INIT_VMI_BIN} ${PREFIXES_DIR}/initrd/sbin/
    COMMAND ${CMAKE_COMMAND} -E chdir ${PREFIXES_DIR}/initrd/ bash ${BOXY_SOURCE_ROOT_DIR}/bflinux/build.sh
    COMMAND ${CMAKE_COMMAND} -E echo initrd built for vmilinux
    VERBATIM
)

add_dependencies(package init-vmi)

fini_project()
