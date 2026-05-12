#!/bin/sh
#
# Copyright (c) 2026 Netflix, Inc.
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Generate eventlog consumer headers from schema files. This script
# generates both individual provider headers and the master header.
#
# Usage:
#   gen_eventlog_headers.sh <schema_dir> <header_dir> <srctop> \
#       <awk_script> <master_header>
#

set -e

SCHEMA_DIR="$1"
HEADER_DIR="$2"
SRCTOP="$3"
AWK_SCRIPT="$4"
MASTER_HEADER="$5"

if [ $# -ne 5 ]; then
	echo "Usage: $0 <schema_dir> <header_dir> <srctop> <awk_script>" \
	    "<master_header>" >&2
	exit 1
fi

# Resolve HEADER_DIR to an absolute path BEFORE any cd operations to
# avoid creating directories in the source tree.
case "${HEADER_DIR}" in
	/*)
		ABS_HEADER_DIR="${HEADER_DIR}"
		;;
	*)
		_ORIG_PWD="${PWD}"
		if command -v realpath >/dev/null 2>&1; then
			ABS_HEADER_DIR="$(realpath -m \
			    "${_ORIG_PWD}/${HEADER_DIR}")"
		else
			if [ "${HEADER_DIR}" = "." ]; then
				ABS_HEADER_DIR="${_ORIG_PWD}"
			elif [ "${HEADER_DIR}" = ".." ]; then
				ABS_HEADER_DIR="$(cd "${_ORIG_PWD}/.." \
				    && pwd)"
			else
				ABS_HEADER_DIR="${_ORIG_PWD}/${HEADER_DIR}"
			fi
		fi
		;;
esac

# Refuse to write inside the source tree.
if [ "${ABS_HEADER_DIR#${SRCTOP}/}" != "${ABS_HEADER_DIR}" ]; then
	echo "ERROR: Header directory ${ABS_HEADER_DIR} would be" \
	    "created inside source tree ${SRCTOP}" >&2
	exit 1
fi

mkdir -p "${ABS_HEADER_DIR}"

# Print one lower-cased provider name per *_eventlog_schema.src found
# under SCHEMA_DIR. Used by the per-provider loops below.
list_providers() {
	[ -d "${SCHEMA_DIR}" ] || return 0
	for schema_path in $(find "${SCHEMA_DIR}" \
	    -name '*_eventlog_schema.src' 2>/dev/null | sort); do
		awk '/^PROVIDER/ {print tolower($2); exit}' \
		    "${schema_path}" 2>/dev/null || true
	done
}

# Step 1: Generate individual consumer headers for each schema.
if [ -d "${SCHEMA_DIR}" ]; then
	for schema_path in $(find "${SCHEMA_DIR}" \
	    -name '*_eventlog_schema.src' 2>/dev/null | sort); do
		provider=$(awk '/^PROVIDER/ {print tolower($2); exit}' \
		    "${schema_path}" 2>/dev/null || true)
		if [ -n "${provider}" ]; then
			(cd "${SRCTOP}" && \
			    awk -v outdir="${ABS_HEADER_DIR}" \
			    -f "${AWK_SCRIPT}" "${schema_path}" -c)
		fi
	done
fi

# Step 2: Generate master consumer header that includes all provider
# headers.
case "${MASTER_HEADER}" in
	/*)
		ABS_MASTER_HEADER="${MASTER_HEADER}"
		;;
	*)
		ABS_MASTER_HEADER="${ABS_HEADER_DIR}/${MASTER_HEADER}"
		;;
esac

cat > "${ABS_MASTER_HEADER}" << 'EOF'
/* Auto-generated consumer header - includes all provider consumer headers */
#ifndef _EVENTLOG_CONSUMER_H_
#define _EVENTLOG_CONSUMER_H_

#include <sys/eventlog.h>
EOF

for provider in $(list_providers); do
	echo "#include \"${provider}_eventlog_consumer.h\"" \
	    >> "${ABS_MASTER_HEADER}"
done

cat >> "${ABS_MASTER_HEADER}" << 'EOF'

/*
 * Check if event is SESSION_END (fixed ID, all providers). Include
 * sys/eventlog.h for EVENTLOG_SESSION_END_ID.
 */
static inline bool
eventlog_is_session_end(const char *provider_name, uint32_t event_id)
{
	(void)provider_name;
	return event_id == EVENTLOG_SESSION_END_ID;
}
EOF

cat >> "${ABS_MASTER_HEADER}" << 'EOF'

/* Master formatting function that routes to per-provider formatters */
static inline int
eventlog_format_payload(const char *provider_name, const void *payload,
    size_t payload_size, uint32_t event_id, char *buf, size_t bufsize)
{
EOF

for provider in $(list_providers); do
	{
		echo "	if (strcmp(provider_name, \"${provider}\") == 0)"
		echo "		return ${provider}_eventlog_format_payload("
		echo "		    payload, payload_size, event_id,"
		echo "		    buf, bufsize);"
	} >> "${ABS_MASTER_HEADER}"
done

cat >> "${ABS_MASTER_HEADER}" << 'EOF'
	return snprintf(buf, bufsize, "[UNKNOWN_PROVIDER:%s]",
	    provider_name);
}
EOF

cat >> "${ABS_MASTER_HEADER}" << 'EOF'

/* Master event ID to name lookup (routes to per-provider lookups) */
static inline const char *
eventlog_event_id_to_name(const char *provider_name, uint32_t event_id)
{
	if (event_id == EVENTLOG_SESSION_END_ID)
		return "SESSION_END";
EOF

for provider in $(list_providers); do
	{
		echo "	if (strcmp(provider_name, \"${provider}\") == 0)"
		echo "		return ${provider}_eventlog_event_id_to_name(" \
		    "event_id);"
	} >> "${ABS_MASTER_HEADER}"
done

cat >> "${ABS_MASTER_HEADER}" << 'EOF'
	return NULL;
}
EOF

cat >> "${ABS_MASTER_HEADER}" << 'EOF'

/* Master keyword name to bitmask lookup (routes to per-provider lookups) */
static inline uint32_t
eventlog_keyword_from_string(const char *provider_name, const char *name)
{
EOF

for provider in $(list_providers); do
	{
		fn="${provider}_eventlog_keyword_from_string"
		echo "	if (strcmp(provider_name, \"${provider}\") == 0)"
		echo "		return ${fn}(name);"
	} >> "${ABS_MASTER_HEADER}"
done

cat >> "${ABS_MASTER_HEADER}" << 'EOF'
	return (0);
}

#endif /* _EVENTLOG_CONSUMER_H_ */
EOF
