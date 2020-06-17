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

# ------------------------------------------------------------------------------
# Buildroot
# ------------------------------------------------------------------------------

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows" OR CMAKE_HOST_SYSTEM_NAME STREQUAL "CYGWIN")
    if(ENABLE_BUILD_EXAMPLES)
        invalid_config("ENABLE_BUILD_EXAMPLES is not supported on Windows. Please use Vagrant.")
    endif()
endif()

if(ENABLE_BUILD_EXAMPLES AND NOT DEFINED REKALL_PROFILE_PATH AND NOT DEFINED VOLATILITY_PROFILE_PATH)
    invalid_config("ENABLE_BUILD_EXAMPLES requires REKALL_PROFILE_PATH or VOLATILITY_PROFILE_PATH")
endif()

if((${REKALL_PROFILE_PATH}) AND NOT EXISTS ${REKALL_PROFILE_PATH})
    message(REKALL_PROFILE_PATH=${REKALL_PROFILE_PATH})
    invalid_config("REKALL_PROFILE_PATH must point to a valid json file")
endif()

if((${VOLATILITY_PROFILE_PATH}) AND NOT EXISTS ${VOLATILITY_PROFILE_PATH})
    message(REKALL_PROFILE_PATH=${REKALL_PROFILE_PATH})
    invalid_config("VOLATILITY_PROFILE_PATH must point to a valid json file")
endif()

# add_config(
#     CONFIG_NAME REKALL_PROFILE_PATH
#     CONFIG_TYPE PATH
#     DESCRIPTION "Rekall profile file path for libvmi"
# )

# add_config(
#     CONFIG_NAME VOLATILITY_PROFILE_PATH
#     CONFIG_TYPE PATH
#     DESCRIPTION "Volatility profile file path for libvmi"
# )