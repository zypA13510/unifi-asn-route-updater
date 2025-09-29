#!/bin/sh
set -eu
UNIFI_HOST=${UNIFI_HOST:-$(ip route show default 0.0.0.0/0 | awk '/default/ {print $3}')}
UNIFI_INSECURE=${UNIFI_INSECURE:-0}
VERBOSE=${VERBOSE:-0}
: "${UNIFI_API_TOKEN}"
: "${ASNLOOKUP_API_TOKEN}"

# Verify UniFi API connection certificate
EXIT_STATUS=0
curl -sf "https://${UNIFI_HOST}/" >/dev/null 2>&1 || EXIT_STATUS=$?
if [ "${EXIT_STATUS}" -eq 0 ]; then
	echo "[INFO] Connecting to ${UNIFI_HOST} using system cacert." >&2
	alias unifi='curl -sSf -H "X-API-KEY: ${UNIFI_API_TOKEN}"'
elif [ -f ./cacert.pem ]; then
	if curl -sf --cacert ./cacert.pem "https://${UNIFI_HOST}/" >/dev/null 2>&1; then
		echo "[INFO] Connecting to ${UNIFI_HOST} using custom cacert." >&2
		alias unifi='curl -sSf --cacert ./cacert.pem -H "X-API-KEY: ${UNIFI_API_TOKEN}"'
	else
		echo "[ERROR] Failed to connect to ${UNIFI_HOST} using custom cacert." >&2
		curl -sSf --cacert ./cacert.pem "https://${UNIFI_HOST}/"
		exit 1
	fi
elif [ "${EXIT_STATUS}" -eq 60 ]; then
	if [ "${UNIFI_INSECURE}" -eq 0 ]; then
		echo "[ERROR] Failed to connect to ${UNIFI_HOST}, SSL certificate problem. Please provide a custom CA certificate in ./cacert.pem or set \$UNIFI_INSECURE=1 (not recommended)." >&2
		curl -sSf "https://${UNIFI_HOST}/"
		exit 1
	fi
	if curl -sfk "https://${UNIFI_HOST}/" >/dev/null 2>&1; then
		echo "[INFO] Connecting to ${UNIFI_HOST} using insecure connection. To secure connection, please provide a custom CA certificate in ./cacert.pem." >&2
		alias unifi='curl -sSfk -H "X-API-KEY: ${UNIFI_API_TOKEN}"'
	else
		echo "[ERROR] Failed to connect to ${UNIFI_HOST} using insecure connection." >&2
		curl -sSfk "https://${UNIFI_HOST}/"
		exit 1
	fi
else
	echo "[ERROR] Failed to connect to ${UNIFI_HOST} using system cacert." >&2
	curl -sSf "https://${UNIFI_HOST}/"
	exit 1
fi

# Verify UniFi API connection credential
if ! unifi "https://${UNIFI_HOST}/proxy/network/integration/v1/info" >/dev/null 2>&1; then
	echo "[ERROR] Failed to request API information from ${UNIFI_HOST}. Please check if \$UNIFI_API_TOKEN is configured correctly." >&2
	unifi "https://${UNIFI_HOST}/proxy/network/integration/v1/info"
	exit 1
fi

# Process rules
RULES_ALL=$(unifi -X GET "https://${UNIFI_HOST}/proxy/network/v2/api/site/default/trafficroutes" -H 'Accept: application/json' | jq -c 'map(select(.enabled))')
MATCHING_RULE_NAMES=$(echo "${RULES_ALL}" | jq -r .[].description | grep '^AS[0-9]* ' | sort | uniq)
if [ "${VERBOSE}" -ne 0 ]; then
	echo "[TRACE] MATCHING_RULE_NAMES=${MATCHING_RULE_NAMES}" >&2
fi
ASNS=$(echo "$MATCHING_RULE_NAMES" | awk '{print $1}' | sort | uniq)
if [ "${VERBOSE}" -ne 0 ]; then
	echo "[TRACE] ASNS=${ASNS}" >&2
fi

for ASN in ${ASNS}; do
	if [ "${VERBOSE}" -ne 0 ]; then
		echo "[TRACE] ASN=${ASN}" >&2
	fi
	ASN_RULE_NAMES=$(echo "${MATCHING_RULE_NAMES}" | grep "^${ASN} ")
	if [ "${VERBOSE}" -ne 0 ]; then
		echo "[TRACE] ASN_RULE_NAMES=${ASN_RULE_NAMES}" >&2
	fi
	ASNLOOKUP=$(curl -sSLf -X GET "https://asn-lookup.p.rapidapi.com/api?asn=${ASN}" -H "x-rapidapi-key: ${ASNLOOKUP_API_TOKEN}") \
		|| (echo "[WARN] Failed to fetch information from ASN Lookup. Skipping ${ASN}." >&2; exit 1) || continue
	ASN_RULE_NAME_PREFIX=$(echo "${ASNLOOKUP}" | jq -r '.[0] | "AS\(.asnHandle) \(.asnName)"')
	if [ "${VERBOSE}" -ne 0 ]; then
		echo "[TRACE] ASN_RULE_NAME_PREFIX=${ASN_RULE_NAME_PREFIX}" >&2
	fi
	echo "${ASN_RULE_NAMES}" | while IFS= read -r ASN_RULE_NAME ; do
		if [ "${VERBOSE}" -ne 0 ]; then
			echo "[TRACE] ASN_RULE_NAME=${ASN_RULE_NAME}" >&2
		fi
		if ! echo "${ASN_RULE_NAME}" | grep -Eq "^${ASN_RULE_NAME_PREFIX}( IPv[46])?\$"; then
			echo "[WARN] Rule name mismatch. Expect: \"${ASN_RULE_NAME_PREFIX}\", found: \"${ASN_RULE_NAME}\". Skipping ${ASN_RULE_NAME}." >&2
			continue
		fi
		NEW_IPS="[]"
		if [ "${VERBOSE}" -ne 0 ]; then
			echo "[TRACE] NEW_IPS=[]" >&2
		fi
		if [ "${ASN_RULE_NAME}" = "${ASN_RULE_NAME_PREFIX}" ] || [ "${ASN_RULE_NAME}" = "${ASN_RULE_NAME_PREFIX} IPv4" ]; then
			NEW_IPS="${NEW_IPS}+$(echo "${ASNLOOKUP}" | jq -r '.[0] | .ipv4_prefix[]' | aggregate6 | jq -cRn '[inputs | select(length > 0)] | map({"ip_or_subnet":.,"ip_version":"v4","port_ranges":[],"ports":[]})')"
			if [ "${VERBOSE}" -ne 0 ]; then
				echo "[TRACE] NEW_IPS+=IPv4" >&2
			fi
		fi
		if [ "${ASN_RULE_NAME}" = "${ASN_RULE_NAME_PREFIX}" ] || [ "${ASN_RULE_NAME}" = "${ASN_RULE_NAME_PREFIX} IPv6" ]; then
			NEW_IPS="${NEW_IPS}+$(echo "${ASNLOOKUP}" | jq -r '.[0] | .ipv6_prefix[]' | aggregate6 | jq -cRn '[inputs | select(length > 0)] | map({"ip_or_subnet":.,"ip_version":"v6","port_ranges":[],"ports":[]})')"
			if [ "${VERBOSE}" -ne 0 ]; then
				echo "[TRACE] NEW_IPS+=IPv6" >&2
			fi
		fi
		NEW_IPS=$(jq -cn "${NEW_IPS}")
		if [ "${VERBOSE}" -ne 0 ]; then
			echo "[TRACE] NEW_IPS=${NEW_IPS}" >&2
		fi
		if [ "${NEW_IPS}" = "[]" ]; then
			echo "[INFO] No IP exists for \"${ASN_RULE_NAME}\", using 192.0.2.0/32 as a placeholder. This rule can be disabled or removed." >&2
			NEW_IPS='[{"ip_or_subnet":"192.0.2.0/32","ip_version":"v4","port_ranges":[],"ports":[]}]'
			if [ "${VERBOSE}" -ne 0 ]; then
				echo "[TRACE] NEW_IPS=[192.0.2.0/32]" >&2
			fi
		fi
		ASN_RULE_IDS=$(echo "${RULES_ALL}" | jq -r '.[] | select(.description == "'"${ASN_RULE_NAME}"'")._id')
		if [ "${VERBOSE}" -ne 0 ]; then
			echo "[TRACE] ASN_RULE_IDS=${ASN_RULE_IDS}" >&2
		fi
		if [ "$(echo "${ASN_RULE_IDS}" | grep -c "^")" -gt 1 ]; then
			echo "[INFO] Found multiple rule entries of \"${ASN_RULE_NAME}\". Updating all matching rules." >&2
		fi
		for ASN_RULE_ID in ${ASN_RULE_IDS}; do
			if [ "${VERBOSE}" -ne 0 ]; then
				echo "[TRACE] ASN_RULE_ID=${ASN_RULE_ID}" >&2
			fi
			ASN_RULE_OLD=$(echo "${RULES_ALL}" | jq -c '.[] | select(._id == "'"${ASN_RULE_ID}"'")')
			OLD_IPS_LIST=$(echo "${ASN_RULE_OLD}" | jq -r ".ip_addresses[].ip_or_subnet" | sort -V)
			if [ "${VERBOSE}" -ne 0 ]; then
				echo "[TRACE] OLD_IPS_LIST=${OLD_IPS_LIST}" >&2
			fi
			NEW_IPS_LIST=$(echo "${NEW_IPS}" | jq -r ".[].ip_or_subnet" | sort -V)
			if [ "${VERBOSE}" -ne 0 ]; then
				echo "[TRACE] NEW_IPS_LIST=${NEW_IPS_LIST}" >&2
			fi
			CHANGESET=$(diff -u0 /dev/fd/3 3<<-EOF /dev/fd/4 4<<-EOF | grep '^[+-][^+-]' || true
${OLD_IPS_LIST}
EOF
${NEW_IPS_LIST}
EOF
			)
			if [ "${VERBOSE}" -ne 0 ]; then
				echo "[TRACE] CHANGESET=${CHANGESET}" >&2
			fi
			if [ -n "${CHANGESET}" ]; then
				if [ "${VERBOSE}" -ne 0 ]; then
					echo "[TRACE] CHANGESET>0" >&2
				fi
				ASN_RULE_NEW=$(echo "${ASN_RULE_OLD}" | jq -c ".ip_addresses=${NEW_IPS}")
				ASN_RULE_URL="https://${UNIFI_HOST}/proxy/network/v2/api/site/default/trafficroutes/${ASN_RULE_ID}"
				if [ "${VERBOSE}" -ne 0 ]; then
					echo "[TRACE] ASN_RULE_URL=${ASN_RULE_URL}" >&2
				fi
				unifi -X PUT "${ASN_RULE_URL}" -d "${ASN_RULE_NEW}" -H 'Accept: application/json' -H 'Content-Type: application/json' >/dev/null
				printf "%s [%s]:\n%s\n" "${ASN_RULE_NAME}" "${ASN_RULE_ID}" "${CHANGESET}"
			fi
		done
	done
done
