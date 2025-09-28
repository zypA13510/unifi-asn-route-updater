#!/bin/sh
set -eu
UNIFI_HOST=${UNIFI_HOST:-$(ip route show default 0.0.0.0/0 | awk '/default/ {print $3}')}
UNIFI_INSECURE=${UNIFI_INSECURE:-0}
: "${UNIFI_API_TOKEN}"
: "${ASNLOOKUP_API_TOKEN}"

# Verify UniFi API connection certificate
EXIT_STATUS=0
curl -sf "https://${UNIFI_HOST}/" || EXIT_STATUS=$?
if [ "${EXIT_STATUS}" -eq 0 ]; then
	echo "[INFO] Connecting to ${UNIFI_HOST} using system cacert." >&2
	alias unifi='curl -sSf -H "X-API-KEY: ${UNIFI_API_TOKEN}"'
elif [ -f ./cacert.pem ]; then
	if ! curl -sf --cacert ./cacert.pem "https://${UNIFI_HOST}/"; then
		echo "[ERROR] Failed to connect to ${UNIFI_HOST} using custom cacert." >&2
		curl -sSf --cacert ./cacert.pem "https://${UNIFI_HOST}/"
		exit 1
	fi
	echo "[INFO] Connecting to ${UNIFI_HOST} using custom cacert." >&2
	alias unifi='curl -sSf --cacert ./cacert.pem -H "X-API-KEY: ${UNIFI_API_TOKEN}"'
elif [ "${EXIT_STATUS}" -eq 60 ]; then
	if [ "${UNIFI_INSECURE}" -eq 0 ]; then
		echo "[ERROR] Failed to connect to ${UNIFI_HOST}, SSL certificate problem. Please provide a custom CA certificate in ./cacert.pem or set \$UNIFI_INSECURE=1 (not recommended)." >&2
		curl -sSf "https://${UNIFI_HOST}/"
		exit 1
	fi
	curl -sfk "https://${UNIFI_HOST}/" || EXIT_STATUS=$?
	if [ "${EXIT_STATUS}" -eq 0 ]; then
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
ASNS=$(echo "$MATCHING_RULE_NAMES" | awk '{print $1}' | sort | uniq)

for ASN in ${ASNS}; do
	ASN_RULE_NAMES=$(echo "${MATCHING_RULE_NAMES}" | grep "^${ASN} ")
	ASNLOOKUP=$(curl -sSLf -X GET "https://asn-lookup.p.rapidapi.com/api?asn=${ASN}" -H "x-rapidapi-key: ${ASNLOOKUP_API_TOKEN}") \
		|| (echo "[WARN] Failed to fetch information from ASN Lookup. Skipping ${ASN}." >&2; exit 1) || continue
	ASN_RULE_NAME_PREFIX=$(echo "${ASNLOOKUP}" | jq -r '.[0] | "AS\(.asnHandle) \(.asnName)"')
	for ASN_RULE_NAME in ${ASN_RULE_NAMES}; do
		if ! echo "${ASN_RULE_NAME}" | grep -Eq "^${ASN_RULE_NAME_PREFIX}( IPv[46])?\$"; then
			echo "[WARN] Rule name mismatch. Expect: \"${ASN_RULE_NAME_PREFIX}\", found: \"${ASN_RULE_NAME}\". Skipping ${ASN_RULE_NAME}." >&2
			continue
		fi
		NEW_IPS="[]"
		if [ "${ASN_RULE_NAME}" = "${ASN_RULE_NAME_PREFIX}" ] || [ "${ASN_RULE_NAME}" = "${ASN_RULE_NAME_PREFIX} IPv4" ]; then
			NEW_IPS="${NEW_IPS}+$(echo "${ASNLOOKUP}" | jq -r '.[0] | .ipv4_prefix[]' | aggregate6 | jq -cRn '[inputs | select(length > 0)] | map({"ip_or_subnet":.,"ip_version":"v4","port_ranges":[],"ports":[]})')"
		fi
		if [ "${ASN_RULE_NAME}" = "${ASN_RULE_NAME_PREFIX}" ] || [ "${ASN_RULE_NAME}" = "${ASN_RULE_NAME_PREFIX} IPv6" ]; then
			NEW_IPS="${NEW_IPS}+$(echo "${ASNLOOKUP}" | jq -r '.[0] | .ipv6_prefix[]' | aggregate6 | jq -cRn '[inputs | select(length > 0)] | map({"ip_or_subnet":.,"ip_version":"v6","port_ranges":[],"ports":[]})')"
		fi
		NEW_IPS=$(jq -cn "${NEW_IPS}")
		if [ "${NEW_IPS}" = "[]" ]; then
			echo "[INFO] No IP exists for \"${ASN_RULE_NAME}\", using 192.0.2.0/32 as a placeholder. This rule can be disabled or removed." >&2
			NEW_IPS='[{"ip_or_subnet":"192.0.2.0/32","ip_version":"v4","port_ranges":[],"ports":[]}]'
		fi
		ASN_RULE_IDS=$(echo "${RULES_ALL}" | jq -r '.[] | select(.description == "'"${ASN_RULE_NAME}"'")._id')
		if [ "$(echo "${ASN_RULE_IDS}" | grep -c "^")" -gt 1 ]; then
			echo "[INFO] Found multiple rule entries of \"${ASN_RULE_NAME}\". Updating all matching rules." >&2
		fi
		for ASN_RULE_ID in ${ASN_RULE_IDS}; do
			ASN_RULE_OLD=$(echo "${RULES_ALL}" | jq -c '.[] | select(._id == "'"${ASN_RULE_ID}"'")')
			OLD_IPS_LIST=$(echo "${ASN_RULE_OLD}" | jq -r ".ip_addresses[].ip_or_subnet" | sort -V)
			NEW_IPS_LIST=$(echo "${NEW_IPS}" | jq -r ".[].ip_or_subnet" | sort -V)
			CHANGESET=$(diff -u0 /dev/fd/3 3<<-EOF /dev/fd/4 4<<-EOF | grep '^[+-][^+-]'
${OLD_IPS_LIST}
EOF
${NEW_IPS_LIST}
EOF
			)
			if [ -n "${CHANGESET}" ]; then
				ASN_RULE_NEW=$(echo "${ASN_RULE_OLD}" | jq -c ".ip_addresses=${NEW_IPS}")
				ASN_RULE_URL="https://${UNIFI_HOST}/proxy/network/v2/api/site/default/trafficroutes/${ASN_RULE_ID}"
				unifi -X PUT "${ASN_RULE_URL}" -d "${ASN_RULE_NEW}" -H 'Accept: application/json' -H 'Content-Type: application/json'
				printf "%s [%s]:\n%s\n" "${ASN_RULE_NAME}" "${ASN_RULE_ID}" "${CHANGESET}"
			fi
		done
	done
done
