#!/bin/bash -e
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

# env REKALL_PROFILE_PATH or VOLATILITY_PROFILE_PATH pointing to a json profile

PROFILE_FILES=(${REKALL_PROFILE_PATH} ${VOLATILITY_PROFILE_PATH})

source "${BR2_EXTERNAL_vmilinux_PATH}/../../scripts/util/colors.sh"

if [[ -z "${REKALL_PROFILE_PATH}" && -z "${VOLATILITY_PROFILE_PATH}" ]]; then
	echo -e "${BF_COLOR_RED}Error: a profile environment variable is required.${BF_COLOR_RST}"
	echo "Please define REKALL_PROFILE_PATH or VOLATILITY_PROFILE_PATH to a json profile"
	exit 1;
fi

LIBVMI_CONF="dom0 {"

for JSON_PROFILE in ${PROFILE_FILES}; do
	if [ ! -f "${JSON_PROFILE}" ]; then
		echo -e "${BF_COLOR_RED}Missing profile file ${JSON_PROFILE}${BF_COLOR_RST}"
		echo ""
		exit 1;
	fi

	[[ $JSON_PROFILE = $REKALL_PROFILE_PATH ]] && JSON_FILE="rekall.json" || JSON_FILE="volatility.json"

	if [ -f "${TARGET_DIR}/root/${JSON_FILE}" ]; then
		echo "removing \${TARGET_DIR}/root/${JSON_FILE})"
		rm ${TARGET_DIR}/root/${JSON_FILE}
	fi

	echo -e "${BF_COLOR_BLU}Copying host profile for libvmi:${BF_COLOR_RST}"
	echo "cp \"${JSON_PROFILE}\" \"${TARGET_DIR}/root/${JSON_FILE}\""
	cp "${JSON_PROFILE}" "${TARGET_DIR}/root/${JSON_FILE}"

	case "${JSON_FILE}" in
		rekall.json)
			LIBVMI_CONF="${LIBVMI_CONF}\n\trekall_profile = \"/root/rekall.json\";"
			;;
		volatility.json)
			LIBVMI_CONF="${LIBVMI_CONF}\n\tvolatility_ist = \"/root/volatility.json\";"
			;;
		*)
			;;
	esac
done

LIBVMI_CONF="${LIBVMI_CONF}\n}"
printf "${LIBVMI_CONF} > \${TARGET_DIR}/etc/libvmi.conf\n"
printf "${LIBVMI_CONF}" > ${TARGET_DIR}/etc/libvmi.conf