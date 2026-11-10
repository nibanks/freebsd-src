#!/usr/bin/awk -f

#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Netflix, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# Script to generate event log header file from schema file.
#
# usage: eventlog_gen.awk <schema.src> -h  (generate producer header for kernel)
#
# The producer header also embeds a flat "decode blob" image of the schema
# (see sys/sys/eventlog_decode.h).  The blob storage is guarded by
# <PROVIDER>_EVENTLOG_DEFINE_DECODE_BLOB; each provider registration site
# defines it to compile in its own private (static) copy, so the schema_id it
# registers always matches the events that translation unit emits - including
# stack modules built out of band against a different schema than the kernel.

function usage()
{
	print "usage: eventlog_gen.awk <schema.src> -h [-o <outfile>]";
	print "  -h  Generate producer header (for event producers)";
	print "  -o  Write output to <outfile> instead of a provider-derived name";
	exit 1;
}

function die(msg, what)
{
	printf srcfile "(" fnr "): " > "/dev/stderr";
	printf msg "\n", what > "/dev/stderr";
	exit 1;
}

# Expected provider name for a schema file: the basename with the
# _eventlog_schema.src suffix removed.  Returns "" for non-conforming names
# (e.g. ad-hoc invocations), which are left unchecked.
function schema_expected_provider(path,   base)
{
	base = path;
	sub(/.*\//, "", base);
	if (base !~ /_eventlog_schema\.src$/)
		return "";
	sub(/_eventlog_schema\.src$/, "", base);
	return base;
}

# Generated header file names derive from the schema file name, while the
# master routing header's #includes and the symbol prefixes derive from
# PROVIDER.  They only resolve if they agree, so reject a mismatch here rather
# than let it surface later as a missing generated #include.
function check_provider_name(prov, path,   expect)
{
	expect = schema_expected_provider(path);
	if (expect != "" && tolower(prov) != expect) {
		printf "eventlog_gen.awk: %s: PROVIDER \"%s\" does not match file name; expected provider \"%s\" (from %s_eventlog_schema.src)\n", \
		    path, prov, expect, expect > "/dev/stderr";
		parse_error = 1;
		exit 1;
	}
}

function printh(s) {
	# Ensure output directory exists (only create once)
	if (hfile != "" && !dir_created) {
		# Extract directory from hfile path
		# CRITICAL: Always use absolute paths to prevent creating dirs in source tree
		if (hfile ~ /^\//) {
			# Absolute path - use dirname approach
			# Remove filename to get directory
			dir_path = hfile;
			sub(/\/[^\/]*$/, "", dir_path);
		} else {
			# Relative path - this should not happen if outdir is set correctly
			# But handle it by making it absolute relative to current directory
			# Get current directory using getline
			"pwd" | getline cwd;
			close("pwd");
			split(hfile, parts, "/");
			dir_path = cwd;
			for (i = 1; i < length(parts); i++) {
				if (parts[i] != "" && parts[i] != ".") {
					if (parts[i] == "..") {
						sub(/\/[^\/]*$/, "", dir_path);
					} else {
						dir_path = dir_path "/" parts[i];
					}
				}
			}
		}
		if (dir_path != "") {
			# Use absolute path - ensure it starts with / to prevent relative interpretation
			# Quote the path to handle spaces/special chars
			cmd = "mkdir -p \"" dir_path "\" 2>/dev/null || true";
			system(cmd);
		}
		dir_created = 1;
	}
	print s > hfile;
}

BEGIN {
	nevents = 0;
	nkeywords = 0;
	nstructs = 0;
	nenums = 0;
	nflags = 0;
	provider = "";
	hfile = "";
	opt_h = 0;
	outfile = "";
	collecting_struct = 0;

	# Build a character->byte-value lookup table for blob byte emission.
	# Start at 1 so a stray sprintf("%c", 0) never seeds an empty key.
	for (oi = 1; oi < 256; oi++)
		ord_table[sprintf("%c", oi)] = oi;
	blob_n = 0;
	collecting_enum = 0;
	collecting_flag = 0;
	struct_line = "";
	enum_line = "";
	flag_line = "";
	dir_created = 0;
	parse_error = 0;

	# Process command line.  Flags may appear in any position relative to the
	# one or more schema files; schema files are left in ARGV for AWK to read.
	nfiles = 0;
	for (i = 1; i < ARGC; i++) {
		if (ARGV[i] == "-h") {
			opt_h = 1;
			ARGV[i] = "";
		} else if (ARGV[i] == "-o") {
			ARGV[i] = "";
			i++;
			if (i >= ARGC)
				usage();
			outfile = ARGV[i];
			ARGV[i] = "";
		} else if (ARGV[i] ~ /^-/) {
			usage();
		} else {
			# Schema file - leave in ARGV so AWK reads it
			nfiles++;
			if (nfiles == 1)
				srcfile = ARGV[i];
		}
	}

	# The -h flag and at least one schema file are required.
	if (opt_h != 1)
		usage();
	if (nfiles < 1)
		usage();

	# Determine output file name (will be set in END after PROVIDER is parsed)
	# hfile is initialized above and will be set in END block

	# Generate header file header (will be done in END after provider is known)
}

/^[ \t]*PROVIDER/ {
	# Remove leading whitespace
	sub(/^[ \t]+/, "");

	# Normalize whitespace - collapse multiple spaces to single space
	gsub(/[ \t]+/, " ");

	if (NF < 2) {
		die("Invalid PROVIDER line: expected PROVIDER <name>");
	}

	if (provider != "") {
		die("PROVIDER already defined");
	}

	provider = $2;
	check_provider_name(provider, FILENAME);
	# Convert to lowercase for filename
	provider_lower = tolower(provider);
	# An explicit -o output path wins; otherwise derive the name from the
	# provider (and optional outdir).
	if (outfile != "") {
		hfile = outfile;
	} else if (outdir != "") {
		hfile = outdir "/" provider_lower "_eventlog.h";
	} else {
		hfile = provider_lower "_eventlog.h";
	}

	next;
}

collecting_struct == 1 {
	# Continuation line for STRUCT
	if (/^[ \t]/) {
		# Remove leading whitespace and append
		sub(/^[ \t]+/, "");
		struct_line = struct_line " " $0;
		next;
	} else {
		# End of continuation - process the accumulated line
		collecting_struct = 0;
		finalize_struct(struct_line);
		struct_line = "";

		# Now process the current line ($0) normally - don't call next
	}
}

/^[ \t]*STRUCT/ {
	# Start collecting STRUCT definition
	if (collecting_struct == 1) {
		# We were already collecting, process the previous one first
		finalize_struct(struct_line);
		struct_line = "";
		collecting_struct = 0;
	}

	# Start new collection
	collecting_struct = 1;
	struct_line = $0;
	sub(/^[ \t]+/, "", struct_line);
	next;
}

/^[ \t]*KEYWORD/ {
	# Remove leading whitespace
	sub(/^[ \t]+/, "");

	# Normalize whitespace - collapse multiple spaces to single space
	gsub(/[ \t]+/, " ");

	if (NF < 3) {
		die("Invalid KEYWORD line: expected KEYWORD <name> <value>");
	}

	nkeywords++;
	keywords[nkeywords, "name"] = $2;
	keywords[nkeywords, "value"] = $3;

	next;
}

collecting_enum == 1 {
	# Continuation line for ENUM
	if (/^[ \t]/) {
		# Remove leading whitespace and append
		sub(/^[ \t]+/, "");
		enum_line = enum_line " " $0;
		next;
	} else {
		# End of continuation - process the accumulated line
		collecting_enum = 0;
		line = enum_line;
		enum_line = "";

		# Normalize whitespace
		gsub(/[ \t]+/, " ", line);
		split(line, fields, " ");

		if (length(fields) < 2) {
			die("Invalid ENUM line: expected ENUM <name> [<value1>:<name1> ...]");
		}

		nenums++;
		enums[nenums, "name"] = fields[2];

		# Collect all value:name pairs
		value_count = 0;
		for (i = 3; i <= length(fields); i++) {
			if (fields[i] == "")
				continue;
			split(fields[i], parts, ":");
			if (length(parts) != 2) {
				die("Invalid enum value definition: " fields[i] " (expected value:name)");
			}
			value_count++;
			enums[nenums, "value", value_count, "num"] = parts[1];
			enums[nenums, "value", value_count, "name"] = parts[2];
		}
		enums[nenums, "value_count"] = value_count;

		# Now process the current line ($0) normally - don't call next
	}
}

/^[ \t]*ENUM/ {
	# Start collecting ENUM definition
	if (collecting_enum == 1) {
		# We were already collecting, process the previous one first
		line = enum_line;
		enum_line = "";
		collecting_enum = 0;

		gsub(/[ \t]+/, " ", line);
		split(line, fields, " ");

		if (length(fields) >= 2) {
			nenums++;
			enums[nenums, "name"] = fields[2];
			value_count = 0;
			for (i = 3; i <= length(fields); i++) {
				if (fields[i] == "")
					continue;
				split(fields[i], parts, ":");
				if (length(parts) == 2) {
					value_count++;
					enums[nenums, "value", value_count, "num"] = parts[1];
					enums[nenums, "value", value_count, "name"] = parts[2];
				}
			}
			enums[nenums, "value_count"] = value_count;
		}
	}

	# Start new collection
	collecting_enum = 1;
	enum_line = $0;
	sub(/^[ \t]+/, "", enum_line);
	next;
}

collecting_flag == 1 {
	# Continuation line for FLAG
	if (/^[ \t]/) {
		# Remove leading whitespace and append
		sub(/^[ \t]+/, "");
		flag_line = flag_line " " $0;
		next;
	} else {
		# End of continuation - process the accumulated line
		collecting_flag = 0;
		line = flag_line;
		flag_line = "";

		# Normalize whitespace
		gsub(/[ \t]+/, " ", line);
		split(line, fields, " ");

		if (length(fields) < 2) {
			die("Invalid FLAG line: expected FLAG <name> [<value1>:<name1> ...]");
		}

		nflags++;
		flags[nflags, "name"] = fields[2];

		# Collect all value:name pairs
		value_count = 0;
		for (i = 3; i <= length(fields); i++) {
			if (fields[i] == "")
				continue;
			split(fields[i], parts, ":");
			if (length(parts) != 2) {
				die("Invalid flag value definition: " fields[i] " (expected value:name)");
			}
			value_count++;
			flags[nflags, "value", value_count, "num"] = parts[1];
			flags[nflags, "value", value_count, "name"] = parts[2];
		}
		flags[nflags, "value_count"] = value_count;

		# Now process the current line ($0) normally - don't call next
	}
}

/^[ \t]*FLAG/ {
	# Start collecting FLAG definition
	# First, process any pending ENUM
	if (collecting_enum == 1 && enum_line != "") {
		line = enum_line;
		enum_line = "";
		collecting_enum = 0;

		gsub(/[ \t]+/, " ", line);
		split(line, fields, " ");

		if (length(fields) >= 2) {
			nenums++;
			enums[nenums, "name"] = fields[2];
			value_count = 0;
			for (i = 3; i <= length(fields); i++) {
				if (fields[i] == "")
					continue;
				split(fields[i], parts, ":");
				if (length(parts) == 2) {
					value_count++;
					enums[nenums, "value", value_count, "num"] = parts[1];
					enums[nenums, "value", value_count, "name"] = parts[2];
				}
			}
			enums[nenums, "value_count"] = value_count;
		}
	}
	if (collecting_flag == 1) {
		# We were already collecting, process the previous one first
		line = flag_line;
		flag_line = "";
		collecting_flag = 0;

		gsub(/[ \t]+/, " ", line);
		split(line, fields, " ");

		if (length(fields) >= 2) {
			nflags++;
			flags[nflags, "name"] = fields[2];
			value_count = 0;
			for (i = 3; i <= length(fields); i++) {
				if (fields[i] == "")
					continue;
				split(fields[i], parts, ":");
				if (length(parts) == 2) {
					value_count++;
					flags[nflags, "value", value_count, "num"] = parts[1];
					flags[nflags, "value", value_count, "name"] = parts[2];
				}
			}
			flags[nflags, "value_count"] = value_count;
		}
	}

	# Start new collection
	collecting_flag = 1;
	flag_line = $0;
	sub(/^[ \t]+/, "", flag_line);
	next;
}

collecting_event == 1 {
	# Continuation line for EVENT
	if (/^[ \t]/) {
		# Remove leading whitespace and append
		sub(/^[ \t]+/, "");
		event_line = event_line " " $0;
		next;
	} else {
		# End of continuation - process the accumulated line
		collecting_event = 0;
		line = event_line;
		event_line = "";

		# Normalize whitespace
		gsub(/[ \t]+/, " ", line);
		split(line, fields, " ");

		if (length(fields) < 7) {
			die("Invalid EVENT line: expected at least 7 fields (name id level keywords struct format)");
		}

		nevents++;
		events[nevents, "name"] = fields[2];
		events[nevents, "id"] = fields[3];
		events[nevents, "level"] = fields[4];
		events[nevents, "keywords"] = fields[5];
		events[nevents, "struct"] = fields[6];

		# Collect format string
		format = "";
		for (i = 7; i <= length(fields); i++) {
			if (i > 7)
				format = format " ";
			format = format fields[i];
		}
		gsub(/^"/, "", format);
		gsub(/"$/, "", format);
		events[nevents, "format"] = format;

		# Now process the current line ($0) normally - don't call next
	}
}

/^[ \t]*EVENT/ {
	# Start collecting EVENT definition
	if (collecting_event == 1) {
		# We were already collecting, process the previous one first
		line = event_line;
		event_line = "";
		collecting_event = 0;

		gsub(/[ \t]+/, " ", line);
		split(line, fields, " ");

		if (length(fields) >= 7) {
			nevents++;
			events[nevents, "name"] = fields[2];
			events[nevents, "id"] = fields[3];
			events[nevents, "level"] = fields[4];
			events[nevents, "keywords"] = fields[5];
			events[nevents, "struct"] = fields[6];
			format = "";
			for (i = 7; i <= length(fields); i++) {
				if (i > 7)
					format = format " ";
				format = format fields[i];
			}
			gsub(/^"/, "", format);
			gsub(/"$/, "", format);
			events[nevents, "format"] = format;
		}
	}

	# Start new collection
	collecting_event = 1;
	event_line = $0;
	sub(/^[ \t]+/, "", event_line);
	next;
}

/^[ \t]*\/\// {
	# Skip C++ style comments (lines starting with //)
	next;
}

/^[ \t]*#/ {
	# Skip comments (lines starting with #)
	next;
}

/^[ \t]*\/\*/ {
	# Skip C-style comment blocks - just skip the line
	next;
}

/^[ \t]*\*/ {
	# Skip comment continuation lines
	next;
}

/^[ \t]*$/ {
	# Skip empty lines
	next;
}

{
	# Unknown line - skip silently (could be part of multi-line comments)
	next;
}

function warn(msg)
{
	printf "eventlog_gen.awk: " msg "\n" > "/dev/stderr";
}

# Parse a STRUCT definition line (whitespace-normalized) into the structs[] tables.
# Called from the grammar entry points and from END for trailing STRUCTs.
function finalize_struct(struct_input,   line, fields, parts, i, j, annotation, ftype, count_field, count_field_idx, max_str, max_val, bracket_pos, colon_pos, head, tail, bparts, fname)
{
	line = struct_input;
	gsub(/[ \t]+/, " ", line);
	split(line, fields, " ");

	if (length(fields) < 2) {
		die("Invalid STRUCT line: expected STRUCT <name> [<field1>:<type1> ...]");
	}

	nstructs++;
	structs[nstructs, "name"] = fields[2];
	structs[nstructs, "has_varlen"] = 0;

	field_count = 0;
	for (i = 3; i <= length(fields); i++) {
		if (fields[i] == "")
			continue;

		# A VARLEN field uses the syntax: name:type[countfield:maxcount]
		# The closing ']' may appear anywhere; we split on ':' only outside
		# the square brackets by stripping the bracket portion first.
		# Distinguish this from the existing fixed char array syntax
		# (name:char[N]) by requiring a ':' inside the brackets.
		bracket_pos = index(fields[i], "[");
		if (bracket_pos > 0) {
			# Everything before '[' is "name:type"; everything between
			# '[' and ']' is "countfield:maxcount".
			if (substr(fields[i], length(fields[i]), 1) != "]") {
				die("Invalid bracketed field: " fields[i] " (missing ']')");
			}
			head = substr(fields[i], 1, bracket_pos - 1);
			tail = substr(fields[i], bracket_pos + 1, length(fields[i]) - bracket_pos - 1);
			# Fixed char[N] (no ':' inside brackets) falls through to the
			# legacy "name:type" parsing below, which treats the full
			# "type[N]" substring as the type spelling.
			if (index(tail, ":") == 0) {
				# Fall through to legacy fixed-size handling.
			} else {
				# VARLEN field
				colon_pos = index(head, ":");
				if (colon_pos == 0) {
					die("Invalid varlen field: " fields[i] " (expected name:type[countfield:max])");
				}
				fname = substr(head, 1, colon_pos - 1);
				ftype = substr(head, colon_pos + 1);
				split(tail, bparts, ":");
				if (length(bparts) != 2) {
					die("Invalid varlen field: " fields[i] " (expected [countfield:max])");
				}
				count_field = bparts[1];
				max_str = bparts[2];
				if (max_str !~ /^[0-9]+$/ || (max_str + 0) == 0) {
					die("Invalid varlen max: " max_str " (must be positive integer)");
				}
				# Disallow char[] and annotations on varlen fields.
				if (ftype == "char" || match(ftype, /^char\[[0-9]+\]$/)) {
					die("Varlen field " fname " may not use char/char[] element type");
				}
				field_count++;
				structs[nstructs, "field", field_count, "name"] = fname;
				structs[nstructs, "field", field_count, "type"] = ftype;
				structs[nstructs, "field", field_count, "is_varlen"] = 1;
				structs[nstructs, "field", field_count, "varlen_count"] = count_field;
				structs[nstructs, "field", field_count, "varlen_max"] = max_val = (max_str + 0);
				structs[nstructs, "has_varlen"] = 1;
				structs[nstructs, "varlen_field_idx"] = field_count;
				# Require varlen to be the last field in the struct.
				# (We enforce this after the loop by checking field_count position.)
				continue;
			}
		}

		# Fixed field: split name:type[:annotation]
		split(fields[i], parts, ":");
		if (length(parts) < 2 || length(parts) > 3) {
			die("Invalid field definition: " fields[i] " (expected field:type[:enum_or_flag_or_hex])");
		}
		field_count++;
		structs[nstructs, "field", field_count, "name"] = parts[1];
		structs[nstructs, "field", field_count, "type"] = parts[2];
		if (length(parts) == 3) {
			annotation = parts[3];
			if (annotation == "hex") {
				structs[nstructs, "field", field_count, "hex_format"] = 1;
			} else if (annotation == "ntohs") {
				structs[nstructs, "field", field_count, "ntohs"] = 1;
			} else if (substr(annotation, 1, 5) == "enum_") {
				structs[nstructs, "field", field_count, "enum_type"] = substr(annotation, 6);
			} else if (substr(annotation, 1, 5) == "flag_") {
				structs[nstructs, "field", field_count, "flag_type"] = substr(annotation, 6);
			} else {
				die("Invalid annotation: " annotation " (expected hex, ntohs, enum_<name>, or flag_<name>)");
			}
		}
	}
	structs[nstructs, "field_count"] = field_count;

	# Validate varlen placement/references.
	if (structs[nstructs, "has_varlen"]) {
		if (structs[nstructs, "varlen_field_idx"] != field_count) {
			die("Varlen field in STRUCT " structs[nstructs, "name"] " must be the last field");
		}
		count_field = structs[nstructs, "field", field_count, "varlen_count"];
		count_field_idx = 0;
		for (j = 1; j < field_count; j++) {
			if (structs[nstructs, "field", j, "name"] == count_field) {
				count_field_idx = j;
				break;
			}
		}
		if (count_field_idx == 0) {
			die("Varlen count field '" count_field "' not found in STRUCT " structs[nstructs, "name"]);
		}
		# The count field must be an unsigned integral type (uint8/16/32/64 or compatible).
		ftype = structs[nstructs, "field", count_field_idx, "type"];
		if (ftype != "uint8_t" && ftype != "uint16_t" && ftype != "uint32_t" &&
		    ftype != "uint64_t" && ftype != "u_char" && ftype != "u_short" &&
		    ftype != "u_int" && ftype != "u_long" && ftype != "size_t") {
			die("Varlen count field '" count_field "' must be an unsigned scalar (got " ftype ")");
		}
		structs[nstructs, "varlen_count_idx"] = count_field_idx;
	}
}

function get_type_size(type)
{
	# Map C types to their sizes (assuming 64-bit platform)
	if (type == "uint8_t" || type == "int8_t" || type == "char" || type == "u_char")
		return 1;
	if (type == "uint16_t" || type == "int16_t" || type == "short" || type == "u_short")
		return 2;
	if (type == "uint32_t" || type == "int32_t" || type == "int" || type == "u_int" || type == "lwpid_t")
		return 4;
	if (type == "uint64_t" || type == "int64_t" || type == "long" || type == "u_long" || type == "size_t")
		return 8;
	if (type == "uintptr_t" || type == "intptr_t")
		return 8;
	if (type == "void*" || type == "void *")
		return 8;  # Pointer size on 64-bit platform
	if (type == "in_addr_t" || type == "struct in_addr")
		return 4;  # IPv4 address is 4 bytes
	if (type == "in6_addr_t" || type == "struct in6_addr")
		return 16;  # IPv6 address is 16 bytes
	# char[N] - fixed-size char array (e.g., char[64])
	if (match(type, /^char\[[0-9]+\]$/)) {
		sub(/^char\[/, "", type);
		sub(/\]$/, "", type);
		return type + 0;
	}
	# Default to 4 bytes for unknown types (conservative)
	warn("Unknown type size for: " type ", assuming 4 bytes");
	return 4;
}

function get_printf_format(field_type, enum_type, flag_type, hex_format)
{
	# Return printf format specifier based on field type
	if (enum_type != "" || flag_type != "")
		return "%s";  # Enum/flag fields are converted to strings
	if (field_type == "in_addr_t" || field_type == "struct in_addr")
		return "%s";  # IP addresses are converted to strings
	if (field_type == "in6_addr_t" || field_type == "struct in6_addr")
		return "%s";  # IPv6 addresses are converted to strings
	if (field_type == "void*" || field_type == "void *")
		return "%p";  # Pointers
	# char[N] - fixed-size char array, treat as string
	if (match(field_type, /^char\[[0-9]+\]$/))
		return "%s";  # Char arrays displayed as strings
	# Handle hex format if requested
	if (hex_format) {
		if (field_type == "uint8_t" || field_type == "u_char")
			return "%x";
		if (field_type == "uint16_t" || field_type == "u_short")
			return "%x";
		if (field_type == "uint32_t" || field_type == "u_int" || field_type == "lwpid_t")
			return "%x";
		if (field_type == "uint64_t" || field_type == "u_long" || field_type == "size_t")
			return "%lx";
	}
	if (field_type == "uint8_t" || field_type == "u_char")
		return "%u";
	if (field_type == "int8_t" || field_type == "char")
		return "%d";
	if (field_type == "uint16_t" || field_type == "u_short")
		return "%u";
	if (field_type == "int16_t" || field_type == "short")
		return "%d";
	if (field_type == "uint32_t" || field_type == "u_int" || field_type == "lwpid_t")
		return "%u";
	if (field_type == "int32_t" || field_type == "int")
		return "%d";
	if (field_type == "uint64_t" || field_type == "u_long" || field_type == "size_t")
		return "%lu";
	if (field_type == "int64_t" || field_type == "long")
		return "%ld";
	# Default to %u for unknown types
	warn("Unknown printf format for type: " field_type ", using %u");
	return "%u";
}

# Map a schema type to an EVENTLOG_DECODE_TYPE_* code (see eventlog_decode.h).
function type_code(t)
{
	if (t == "uint8_t" || t == "u_char")		return 1;	# U8
	if (t == "int8_t" || t == "char")		return 5;	# I8
	if (t == "uint16_t" || t == "u_short")		return 2;	# U16
	if (t == "int16_t" || t == "short")		return 6;	# I16
	if (t == "uint32_t" || t == "u_int" || t == "lwpid_t")
							return 3;	# U32
	if (t == "int32_t" || t == "int")		return 7;	# I32
	if (t == "uint64_t" || t == "u_long" || t == "size_t")
							return 4;	# U64
	if (t == "int64_t" || t == "long")		return 8;	# I64
	if (t == "uintptr_t" || t == "intptr_t")	return 4;	# U64-width
	if (t == "void*" || t == "void *")		return 9;	# PTR
	if (t == "in_addr_t" || t == "struct in_addr")	return 10;	# IN_ADDR
	if (t == "in6_addr_t" || t == "struct in6_addr") return 11;	# IN6_ADDR
	if (match(t, /^char\[[0-9]+\]$/))		return 12;	# CHAR_ARRAY
	return 3;	# default U32
}

# Parse a 0x... hex string into a number (one-true-awk has no strtonum).
function parse_hex(s,   n, i, c, d)
{
	sub(/^0[xX]/, "", s);
	n = 0;
	for (i = 1; i <= length(s); i++) {
		c = tolower(substr(s, i, 1));
		d = index("0123456789abcdef", c) - 1;
		if (d < 0)
			break;
		n = n * 16 + d;
	}
	return n;
}

# Convert a schema-supplied numeric literal (e.g. an ENUM/FLAG value or event
# id) to a number, honoring 0x.. hex.  one-true-awk evaluates "0x02"+0 as 0, so
# hex literals must be parsed explicitly rather than coerced.
function to_num(s)
{
	if (s ~ /^0[xX][0-9a-fA-F]+$/)
		return parse_hex(s);
	return s + 0;
}

# Resolve a KEYWORD value spelling to its numeric bitmask, mirroring the
# producer's #define logic (hex as-is, small decimal as a bit position,
# large decimal as-is).
function kw_numeric(val,   num)
{
	if (val ~ /^0x[0-9a-fA-F]+$/)
		return parse_hex(val);
	if (val ~ /^[0-9]+$/) {
		num = val + 0;
		if (num < 16)
			return 2 ^ (num - 1);
		return num;
	}
	return 0;
}

# Bitwise OR for values up to 32 bits (one-true-awk has no or()).
function bor(a, b,   r, bit)
{
	r = 0;
	bit = 1;
	while (a > 0 || b > 0) {
		if ((a % 2) == 1 || (b % 2) == 1)
			r = r + bit;
		a = int(a / 2);
		b = int(b / 2);
		bit = bit * 2;
	}
	return r;
}

# Look up a keyword by exact name; returns its 1-based index, or 0 if unknown.
function keyword_index_by_name(name,   i)
{
	for (i = 1; i <= nkeywords; i++)
		if (keywords[i, "name"] == name)
			return i;
	return 0;
}

# True if `name` appears as an exact comma-delimited token in an event's
# keyword field.  Used instead of index()-based substring matching, which
# would let e.g. STREAM silently set UPSTREAM's bit.
function keyword_field_has(kwstr, name,   n, toks, j, tok)
{
	n = split(kwstr, toks, ",");
	for (j = 1; j <= n; j++) {
		tok = toks[j];
		gsub(/^[ \t]+|[ \t]+$/, "", tok);
		if (tok == name)
			return 1;
	}
	return 0;
}

# Validate that every token in an event's keyword field names a declared
# keyword.  An unknown token (a typo, or a substring that used to match by
# accident) is a schema error rather than being silently ignored.
function check_event_keywords(kwstr, evtname,   n, toks, j, tok)
{
	n = split(kwstr, toks, ",");
	for (j = 1; j <= n; j++) {
		tok = toks[j];
		gsub(/^[ \t]+|[ \t]+$/, "", tok);
		if (tok == "")
			continue;
		if (keyword_index_by_name(tok) == 0)
			die("Unknown keyword in event " evtname ": %s", tok);
	}
}

# OR together the keyword bitmasks named in an event's keyword field.  Tokens
# are matched exactly (see keyword_field_has); declared-keyword order is
# preserved so the resulting mask and macro text are independent of how the
# event lists its keywords.
function event_keywords_value(kwstr, evtname,   j, v)
{
	check_event_keywords(kwstr, evtname);
	v = 0;
	for (j = 1; j <= nkeywords; j++) {
		if (keyword_field_has(kwstr, keywords[j, "name"]))
			v = bor(v, kw_numeric(keywords[j, "value"]));
	}
	return v;
}

# Numeric enum eventlog_level for a schema level name.
function level_numeric(l)
{
	if (l == "ERROR")	return 1;
	if (l == "WARN")	return 2;
	if (l == "INFO")	return 3;
	if (l == "VERBOSE")	return 4;
	if (l == "TRACE")	return 5;
	return 3;	# default INFO
}

function enum_index_by_name(n,   i)
{
	for (i = 1; i <= nenums; i++)
		if (enums[i, "name"] == n)
			return i;
	return 0;
}

function flag_index_by_name(n,   i)
{
	for (i = 1; i <= nflags; i++)
		if (flags[i, "name"] == n)
			return i;
	return 0;
}

function struct_index_for_event(sname,   i)
{
	if (sname == "NONE")
		return 0;
	for (i = 1; i <= nstructs; i++)
		if (structs[i, "name"] == sname)
			return i;
	return 0;
}

# Little-endian byte emission into blob_bytes[0 .. blob_n-1].
function emit_byte(v)		{ blob_bytes[blob_n++] = int(to_num(v)) % 256; }
function emit_u8(v)		{ emit_byte(v); }
function emit_u16(v,   x)
{
	x = to_num(v);
	emit_byte(x % 256);
	emit_byte(int(x / 256) % 256);
}
function emit_u32(v,   x)
{
	x = to_num(v);
	emit_byte(x % 256); x = int(x / 256);
	emit_byte(x % 256); x = int(x / 256);
	emit_byte(x % 256); x = int(x / 256);
	emit_byte(x % 256);
}
function emit_str(s,   i, n)
{
	n = length(s);
	emit_u16(n);
	for (i = 1; i <= n; i++)
		emit_byte(ord_table[substr(s, i, 1)]);
}

# Build the flat decode blob (see eventlog_decode.h) into blob_bytes[].
function serialize_blob(   i, j, fc, off, sz, t, ti, ann, ai, clen, fl, vci, vmax)
{
	# Header: magic "EDB1", version, word-size/endianness descriptor,
	# provider name, section counts.  word_size=8 (64-bit), endianness=0
	# (little-endian), reserved=0; see sys/sys/eventlog_decode.h.
	emit_byte(69); emit_byte(68); emit_byte(66); emit_byte(49);
	emit_u16(1);
	emit_u8(8);
	emit_u8(0);
	emit_u16(0);
	emit_str(tolower(provider));
	emit_u16(nkeywords);
	emit_u16(nenums);
	emit_u16(nflags);
	emit_u16(nstructs);
	emit_u16(nevents);

	for (i = 1; i <= nkeywords; i++) {
		emit_str(keywords[i, "name"]);
		emit_u32(kw_numeric(keywords[i, "value"]));
	}

	for (i = 1; i <= nenums; i++) {
		emit_str(enums[i, "name"]);
		emit_u16(enums[i, "value_count"]);
		for (j = 1; j <= enums[i, "value_count"]; j++) {
			emit_u32(enums[i, "value", j, "num"]);
			emit_str(enums[i, "value", j, "name"]);
		}
	}

	for (i = 1; i <= nflags; i++) {
		emit_str(flags[i, "name"]);
		emit_u16(flags[i, "value_count"]);
		for (j = 1; j <= flags[i, "value_count"]; j++) {
			emit_u32(flags[i, "value", j, "num"]);
			emit_str(flags[i, "value", j, "name"]);
		}
	}

	for (i = 1; i <= nstructs; i++) {
		emit_str(structs[i, "name"]);
		fc = structs[i, "field_count"];
		emit_u16(fc);
		off = 0;
		for (j = 1; j <= fc; j++) {
			t = structs[i, "field", j, "type"];
			ti = type_code(t);
			sz = get_type_size(t);

			emit_str(structs[i, "field", j, "name"]);
			emit_u8(ti);

			ann = 0; ai = 0;
			if (structs[i, "field", j, "enum_type"] != "") {
				ann = 3;
				ai = enum_index_by_name(structs[i, "field", j, "enum_type"]);
			} else if (structs[i, "field", j, "flag_type"] != "") {
				ann = 4;
				ai = flag_index_by_name(structs[i, "field", j, "flag_type"]);
			} else if (structs[i, "field", j, "hex_format"] == 1) {
				ann = 1;
			} else if (structs[i, "field", j, "ntohs"] == 1) {
				ann = 2;
			}
			emit_u8(ann);
			emit_u16(ai);

			clen = 0;
			if (match(t, /^char\[[0-9]+\]$/))
				clen = substr(t, RSTART + 5, RLENGTH - 6) + 0;
			emit_u16(clen);

			emit_u16(off);

			fl = 0; vci = 0; vmax = 0;
			if (structs[i, "field", j, "is_varlen"] == 1) {
				fl = 1;
				vci = structs[i, "varlen_count_idx"];
				vmax = structs[i, "field", j, "varlen_max"];
			}
			emit_u8(fl);
			emit_u16(vci);
			emit_u16(vmax);

			off = off + sz;
		}
	}

	for (i = 1; i <= nevents; i++) {
		emit_u32(events[i, "id"]);
		emit_str(events[i, "name"]);
		emit_u8(level_numeric(events[i, "level"]));
		emit_u32(event_keywords_value(events[i, "keywords"], events[i, "name"]));
		emit_u16(struct_index_for_event(events[i, "struct"]));
		emit_str(events[i, "format"]);
	}
}

# Emit the decode-blob storage into the producer header.  The byte array is a
# private (static) copy compiled only in the translation unit that defines
# <PROVIDER>_EVENTLOG_DEFINE_DECODE_BLOB (the provider's registration site), so
# each registrant carries the blob matching the events it emits.
function emit_blob_storage(   i, line, cnt, pl, guard)
{
	pl = tolower(provider);
	guard = toupper(provider) "_EVENTLOG_DEFINE_DECODE_BLOB";

	printh("/*");
	printh(" * Flat decode-blob image of the " pl " provider schema (see");
	printh(" * sys/sys/eventlog_decode.h).  Define " guard);
	printh(" * to compile this private copy into a provider registration site;");
	printh(" * each site carries its own copy so the schema_id it registers");
	printh(" * matches the events it emits, even when built out of band from the");
	printh(" * running kernel.");
	printh(" */");
	printh("#ifdef " guard);
	printh("static const unsigned char " pl "_eventlog_decode_blob[] = {");
	line = "";
	cnt = 0;
	for (i = 0; i < blob_n; i++) {
		if (cnt == 0)
			line = "\t";
		line = line sprintf("0x%02x, ", blob_bytes[i]);
		cnt++;
		if (cnt == 12) {
			printh(line);
			line = "";
			cnt = 0;
		}
	}
	if (cnt > 0)
		printh(line);
	printh("};");
	printh("static const unsigned int " pl "_eventlog_decode_blob_size = " blob_n ";");
	printh("#endif");
	printh("");
}

END {
	# A fatal parse error (e.g. provider/file-name mismatch) set parse_error
	# and exited mid-rule; awk still runs END, so bail before producing any
	# output.  The bare exit preserves the status already set by exit 1.
	if (parse_error)
		exit;

	# Process any remaining collected STRUCT
	if (collecting_struct == 1 && struct_line != "") {
		finalize_struct(struct_line);
		struct_line = "";
		collecting_struct = 0;
	}

	# Process any remaining collected EVENT
	if (collecting_event == 1 && event_line != "") {
		line = event_line;
		gsub(/[ \t]+/, " ", line);
		split(line, fields, " ");

		if (length(fields) >= 7) {
			nevents++;
			events[nevents, "name"] = fields[2];
			events[nevents, "id"] = fields[3];
			events[nevents, "level"] = fields[4];
			events[nevents, "keywords"] = fields[5];
			events[nevents, "struct"] = fields[6];
			format = "";
			for (i = 7; i <= length(fields); i++) {
				if (i > 7)
					format = format " ";
				format = format fields[i];
			}
			gsub(/^"/, "", format);
			gsub(/"$/, "", format);
			events[nevents, "format"] = format;
		}
	}

	# Process any remaining collected ENUM
	if (collecting_enum == 1 && enum_line != "") {
		line = enum_line;
		gsub(/[ \t]+/, " ", line);
		split(line, fields, " ");

		if (length(fields) >= 2) {
			nenums++;
			enums[nenums, "name"] = fields[2];
			value_count = 0;
			for (i = 3; i <= length(fields); i++) {
				if (fields[i] == "")
					continue;
				split(fields[i], parts, ":");
				if (length(parts) == 2) {
					value_count++;
					enums[nenums, "value", value_count, "num"] = parts[1];
					enums[nenums, "value", value_count, "name"] = parts[2];
				}
			}
			enums[nenums, "value_count"] = value_count;
		}
	}

	# Process any remaining collected FLAG
	if (collecting_flag == 1 && flag_line != "") {
		line = flag_line;
		gsub(/[ \t]+/, " ", line);
		split(line, fields, " ");

		if (length(fields) >= 2) {
			nflags++;
			flags[nflags, "name"] = fields[2];
			value_count = 0;
			for (i = 3; i <= length(fields); i++) {
				if (fields[i] == "")
					continue;
				split(fields[i], parts, ":");
				if (length(parts) == 2) {
					value_count++;
					flags[nflags, "value", value_count, "num"] = parts[1];
					flags[nflags, "value", value_count, "name"] = parts[2];
				}
			}
			flags[nflags, "value_count"] = value_count;
		}
	}

	if (provider == "") {
		die("PROVIDER must be defined at the beginning of the schema file");
	}

	if (nevents == 0) {
		die("No events found in schema file");
	}

	# Add KEYWORD SESSION for reserved events (0x80000000 = EVENTLOG_KEYWORD_SESSION)
	for (i = 1; i <= nkeywords; i++) {
		if (keywords[i, "name"] == "SESSION")
			break;
	}
	if (i > nkeywords) {
		nkeywords++;
		keywords[nkeywords, "name"] = "SESSION";
		keywords[nkeywords, "value"] = "0x80000000";
	}
	# Add struct for SESSION_CREATE payload if schema does not define it
	has_session_create = 0;
	for (si = 1; si <= nstructs; si++) {
		if (structs[si, "name"] == "SESSION_CREATE") {
			has_session_create = 1;
			break;
		}
	}
	if (!has_session_create) {
		nstructs++;
		structs[nstructs, "name"] = "SESSION_CREATE";
		structs[nstructs, "field", 1, "name"] = "_unused";
		structs[nstructs, "field", 1, "type"] = "uint8_t";
		structs[nstructs, "field_count"] = 1;
	}
	# SESSION_END / DUMP_COMPLETE have no payload - use NONE struct
	# Add reserved events with fixed IDs (UINT32_MAX-2..UINT32_MAX) if not in schema
	has_session_create_evt = 0;
	has_session_end_evt = 0;
	has_dump_complete_evt = 0;
	for (ei = 1; ei <= nevents; ei++) {
		if (events[ei, "name"] == "SESSION_CREATE") has_session_create_evt = 1;
		if (events[ei, "name"] == "SESSION_END") has_session_end_evt = 1;
		if (events[ei, "name"] == "DUMP_COMPLETE") has_dump_complete_evt = 1;
	}
	if (!has_session_create_evt) {
		nevents++;
		events[nevents, "name"] = "SESSION_CREATE";
		events[nevents, "id"] = 4294967294;  # UINT32_MAX-1
		events[nevents, "level"] = "INFO";
		events[nevents, "keywords"] = "SESSION";
		events[nevents, "struct"] = "SESSION_CREATE";
		events[nevents, "format"] = "Session created";
	}
	if (!has_session_end_evt) {
		nevents++;
		events[nevents, "name"] = "SESSION_END";
		events[nevents, "id"] = 4294967295;  # UINT32_MAX
		events[nevents, "level"] = "INFO";
		events[nevents, "keywords"] = "SESSION";
		events[nevents, "struct"] = "NONE";
		events[nevents, "format"] = "Session ended";
	}
	if (!has_dump_complete_evt) {
		nevents++;
		events[nevents, "name"] = "DUMP_COMPLETE";
		events[nevents, "id"] = 4294967293;  # UINT32_MAX-2
		events[nevents, "level"] = "INFO";
		events[nevents, "keywords"] = "SESSION";
		events[nevents, "struct"] = "NONE";
		events[nevents, "format"] = "Dump complete";
	}

	if (hfile == "" && outfile != "") {
		hfile = outfile;
	}
	if (hfile == "") {
		provider_lower = tolower(provider);
		# If outdir was provided via -v outdir=..., use it
		if (outdir != "") {
			hfile = outdir "/" provider_lower "_eventlog.h";
		} else {
			hfile = provider_lower "_eventlog.h";
		}
	}

	# Serialize the schema into the flat decode image now so the bytes are
	# ready to embed in the producer header below.
	serialize_blob();

	# Generate header file header.  Use the schema basename (not its full
	# path) so output is independent of where the generator is invoked from.
	generated = "@" "generated";
	srcbase = srcfile;
	sub(/.*\//, "", srcbase);
	printh("/*");
	printh(" * THIS FILE AUTOMATICALLY GENERATED.  DO NOT EDIT.");
	printh(" *");
	printh(" * Generated from " srcbase);
	printh(" * by eventlog_gen.awk");
	printh(" */");
	printh("");
	printh("#ifndef _" toupper(provider) "_EVENTLOG_H_");
	printh("#define _" toupper(provider) "_EVENTLOG_H_");
	printh("");
	printh("#include <sys/eventlog.h>");
	# Check if any struct uses in_addr, in6_addr, char[N], or declares a
	# trailing variable-length array.
	needs_inet = 0;
	needs_inet6 = 0;
	needs_string = 0;
	needs_iovec = 0;
	for (i = 1; i <= nstructs; i++) {
		if (structs[i, "has_varlen"] == 1)
			needs_iovec = 1;
		field_count = structs[i, "field_count"];
		for (j = 1; j <= field_count; j++) {
			field_type = structs[i, "field", j, "type"];
			if (field_type == "in_addr_t" || field_type == "struct in_addr")
				needs_inet = 1;
			if (field_type == "in6_addr_t" || field_type == "struct in6_addr")
				needs_inet6 = 1;
			if (match(field_type, /^char\[[0-9]+\]$/))
				needs_string = 1;
		}
	}
	if (needs_inet || needs_inet6)
		printh("#include <netinet/in.h>");
	# Producer string/iovec helpers.  The producer header is portable: the
	# SAME generated header (and the SAME LOG macros) compile in the kernel
	# and in user space.  strncpy/bzero/memcpy come from libkern in the
	# kernel and libc in userland; memcpy is used by packed varlen accessors.
	if (needs_string || needs_iovec) {
		printh("#if defined(_KERNEL)");
		printh("#include <sys/libkern.h>");
		printh("#else");
		printh("#include <string.h>");
		printh("#include <strings.h>");
		printh("#endif");
	}
	# struct iovec for the gather write path (valid in kernel and userland).
	if (needs_iovec)
		printh("#include <sys/uio.h>");
	# The producer runtime (struct eventlog_session +
	# eventlog_event_write[_gather]) comes from <sys/eventlog.h> (included
	# above): the _KERNEL half in the kernel, the libeventlog half under
	# !_KERNEL.
	printh("");

	# Generate provider instance and macros at the top
	provider_upper = toupper(provider);
	provider_lower = tolower(provider);

	# Embed the flat decode blob (see sys/sys/eventlog_decode.h).  A provider
	# registers a pointer to it so runtime decoders (e.g. elog) can interpret
	# events without per-provider generated C.  Storage is a private copy
	# emitted only in the translation unit that defines
	# <PROVIDER>_EVENTLOG_DEFINE_DECODE_BLOB (the registration site).
	emit_blob_storage();

	# Calculate maximum event size by finding the largest struct.
	# For varlen structs, the max includes the tail: sizeof(fixed head) + max_elements * sizeof(element).
	max_size = 0;
	for (i = 1; i <= nevents; i++) {
		struct_name = events[i, "struct"];
		if (struct_name == "NONE")
			continue;
		struct_idx = 0;
		for (j = 1; j <= nstructs; j++) {
			if (structs[j, "name"] == struct_name) {
				struct_idx = j;
				break;
			}
		}
		if (struct_idx == 0) {
			die("Struct " struct_name " not found for event " events[i, "name"]);
		}
		field_count = structs[struct_idx, "field_count"];
		event_size = 0;
		for (j = 1; j <= field_count; j++) {
			field_type = structs[struct_idx, "field", j, "type"];
			if (structs[struct_idx, "field", j, "is_varlen"] == 1) {
				event_size += get_type_size(field_type) * structs[struct_idx, "field", j, "varlen_max"];
			} else {
				event_size += get_type_size(field_type);
			}
		}
		if (event_size > max_size) {
			max_size = event_size;
		}
	}


	# Generate struct type definitions.
	# For varlen structs the trailing array is NOT declared as a C member --
	# callers access it through the generated accessor helper. We emit a
	# comment documenting the wire layout.
	printh("/* Event data structures */");
	for (i = 1; i <= nstructs; i++) {
		struct_name = structs[i, "name"];
		field_count = structs[i, "field_count"];
		# All event structs are __packed so the on-disk wire bytes are
		# exactly the sum of field bytes -- no inter-field padding, no
		# trailing pad to natural alignment.  This eliminates the
		# "trailing pad leaks uninitialized stack" class of bugs (a
		# field-by-field assignment in _LOG_ALWAYS now fully covers the
		# struct) and keeps captures dense.  Trailing-array consumers
		# read evt + sizeof(*evt) at potentially-unaligned offsets;
		# amd64 (our only target) handles unaligned scalar loads
		# transparently.
		printh("struct " provider_lower "_eventlog_" tolower(struct_name) " {");
		for (j = 1; j <= field_count; j++) {
			field_name = structs[i, "field", j, "name"];
			field_type = structs[i, "field", j, "type"];
			if (structs[i, "field", j, "is_varlen"] == 1) {
				# Documentation only - the trailing array lives in the wire payload,
				# not in this C struct. Use the accessor helper to read it.
				printh("\t/* Followed on the wire by " field_type " " field_name \
				    "[" structs[i, "field", j, "varlen_count"] "]; " \
				    "max " structs[i, "field", j, "varlen_max"] " elements */");
				continue;
			}
			# Map special types to their C equivalents
			if (field_type == "in_addr_t")
				field_type = "struct in_addr";
			else if (field_type == "in6_addr_t")
				field_type = "struct in6_addr";
			# char[N] -> char field_name[N];
			if (match(field_type, /^char\[([0-9]+)\]$/)) {
				array_size = substr(field_type, RSTART + 5, RLENGTH - 6);
				printh("\tchar\t" field_name "[" array_size "];");
			} else {
				printh("\t" field_type "\t" field_name ";");
			}
		}
		printh("} __packed;");
		# Emit a MAX constant + accessor helper for any varlen field.
		if (structs[i, "has_varlen"] == 1) {
			vidx = structs[i, "varlen_field_idx"];
			vname = structs[i, "field", vidx, "name"];
			vtype = structs[i, "field", vidx, "type"];
			vcount = structs[i, "field", vidx, "varlen_count"];
			vmax_define = toupper(provider) "_EVENTLOG_" toupper(struct_name) \
			    "_" toupper(vname) "_MAX";
			printh("#define\t" vmax_define "\t" \
			    structs[i, "field", vidx, "varlen_max"]);
			printh("");
			printh("/*");
			printh(" * Copy the trailing " vname "[] array out of a " struct_name " wire");
			printh(" * payload into the caller-supplied out[] buffer, which must have room");
			printh(" * for at least " vmax_define " elements. Returns the number of elements");
			printh(" * copied, or 0 if the payload is malformed.");
			printh(" *");
			printh(" * The event struct is __packed (dense wire layout, no padding), so the");
			printh(" * trailing array starts at an offset that need not satisfy");
			printh(" * _Alignof(" vtype "). We must not hand back a typed pointer into that");
			printh(" * memory -- dereferencing it faults on strict-alignment architectures.");
			printh(" * memcpy() reads the unaligned bytes safely on every architecture.");
			printh(" */");
			printh("static inline size_t");
			printh(provider_lower "_eventlog_" tolower(struct_name) "_" tolower(vname) \
			    "(const struct " provider_lower "_eventlog_" tolower(struct_name) " *evt, size_t payload_size, " vtype " *out)");
			printh("{");
			printh("\tsize_t __head = sizeof(*evt);");
			printh("\tsize_t __n = (size_t)evt->" vcount ";");
			printh("\tif (__n > " vmax_define ")");
			printh("\t\treturn 0;");
			printh("\tif (payload_size < __head + __n * sizeof(" vtype "))");
			printh("\t\treturn 0;");
			printh("\tmemcpy(out, (const char *)evt + __head, __n * sizeof(" vtype "));");
			printh("\treturn __n;");
			printh("}");
		}
		printh("");
	}

	# Generate keyword flag definitions
	printh("/* Event keyword flags */");
	# Keywords defined in schema
	next_bit = 0x0001;  # Start from first bit
	for (i = 1; i <= nkeywords; i++) {
		# Convert value to hex if it's numeric, otherwise use as-is
		value = keywords[i, "value"];
		if (value ~ /^0x[0-9a-fA-F]+$/) {
			# Already hex - use as-is
			printh("#define\t" toupper(provider) "_EVENTLOG_KEYWORD_" keywords[i, "name"] "\t" value);
		} else if (value ~ /^[0-9]+$/) {
			# Decimal - if it's a small number (like 1), treat as relative bit position
			# Otherwise use the value directly converted to hex
			num_value = value + 0;
			if (num_value < 16) {
				# Small number - treat as relative bit position
				# 1 = first bit (0x0001), 2 = second bit (0x0002), etc.
				# Calculate: 2^(num_value-1)
				bit_shift = num_value - 1;
				bit_value = 2 ^ bit_shift;
				printh("#define\t" toupper(provider) "_EVENTLOG_KEYWORD_" keywords[i, "name"] "\t0x" sprintf("%04x", bit_value));
			} else {
				# Large number - use directly as hex
				printh("#define\t" toupper(provider) "_EVENTLOG_KEYWORD_" keywords[i, "name"] "\t0x" sprintf("%04x", num_value));
			}
		} else {
			# Use as-is (might be a constant)
			printh("#define\t" toupper(provider) "_EVENTLOG_KEYWORD_" keywords[i, "name"] "\t" value);
		}
	}
	printh("");

	# Generate enum constant definitions
	if (nenums > 0) {
		printh("/* Enum constant definitions */");
		for (i = 1; i <= nenums; i++) {
			enum_name = enums[i, "name"];
			value_count = enums[i, "value_count"];
			for (j = 1; j <= value_count; j++) {
				value_num = enums[i, "value", j, "num"];
				value_name = enums[i, "value", j, "name"];
				printh("#define\t" toupper(provider) "_EVENTLOG_" toupper(enum_name) "_" toupper(value_name) "\t" value_num);
			}
		}
		printh("");
	}

	# Generate flag constant definitions
	if (nflags > 0) {
		printh("/* Flag constant definitions */");
		for (i = 1; i <= nflags; i++) {
			flag_name = flags[i, "name"];
			value_count = flags[i, "value_count"];
			for (j = 1; j <= value_count; j++) {
				value_num = flags[i, "value", j, "num"];
				value_name = flags[i, "value", j, "name"];
				printh("#define\t" toupper(provider) "_EVENTLOG_FLAG_" toupper(value_name) "\t" value_num);
			}
		}
		printh("");
	}

	# Generate event ID constants
	printh("/* Event ID constants */");
	for (i = 1; i <= nevents; i++) {
		printh("#define\t" toupper(provider) "_EVENTLOG_" events[i, "name"] "_ID\t" events[i, "id"]);
	}
	printh("");

	# Generate event definitions.
	{
		printh("/* Events */");
		printh("");

		for (i = 1; i <= nevents; i++) {
		# Convert level to enum value
		level_enum = "EVENTLOG_LEVEL_INFO";
		if (events[i, "level"] == "ERROR")
			level_enum = "EVENTLOG_LEVEL_ERROR";
		else if (events[i, "level"] == "WARN")
			level_enum = "EVENTLOG_LEVEL_WARN";
		else if (events[i, "level"] == "VERBOSE")
			level_enum = "EVENTLOG_LEVEL_VERBOSE";
		else if (events[i, "level"] == "TRACE")
			level_enum = "EVENTLOG_LEVEL_TRACE";

		# Parse keywords into keyword_flags.  Match the comma-separated
		# tokens exactly against the declared keywords (see
		# event_keywords_value); an unknown token is a schema error.
		keywords_str = events[i, "keywords"];
		keyword_flags = "";
		check_event_keywords(keywords_str, events[i, "name"]);
		# Only use keywords explicitly defined in schema
		for (j = 1; j <= nkeywords; j++) {
			keyword_name = keywords[j, "name"];
			if (keyword_field_has(keywords_str, keyword_name))
				keyword_flags = keyword_flags " | " toupper(provider) "_EVENTLOG_KEYWORD_" keyword_name;
		}

		# Remove leading " | "
		if (keyword_flags != "") {
			# Remove leading space and " | " (substring starting at position 4)
			keyword_flags = substr(keyword_flags, 4);
		} else {
			keyword_flags = "0";
		}

		# Generate defines for event
		event_name = events[i, "name"];
		struct_name = events[i, "struct"];
		provider_upper = toupper(provider);
		provider_lower = tolower(provider);

		# Generate comment block for this event
		printh("/*");
		printh(" * " provider_upper " " event_name " Event");
		printh(" */");
		printh("");

		# Generate enabled macro.  The session's effective level/keywords
		# are read through the EVENTLOG_SESSION_EFFECTIVE_* accessors so
		# the identical macro works in the kernel (direct fields) and in
		# user space (read through the ->eff indirection in libeventlog).
		printh("#define " provider_upper "_EVENTLOG_" event_name "_ENABLED(__session) \\");
		printh("\t((__session != NULL) && \\");
		printh("\t (EVENTLOG_SESSION_EFFECTIVE_LEVEL(__session) >= " level_enum ") && \\");
		printh("\t ((EVENTLOG_SESSION_EFFECTIVE_KEYWORDS(__session) & (" keyword_flags ")) != 0))");
		printh("");

		if (struct_name == "NONE") {
			# No-payload event: macros take only __session
			printh("/* struct eventlog_session *session */");
			printh("#define " provider_upper "_EVENTLOG_" event_name "_LOG_ALWAYS(__session) \\");
			printh("\tdo { \\");
			printh("\t\teventlog_event_write(__session, " events[i, "id"] ", " level_enum ", (" keyword_flags "), NULL, 0); \\");
			printh("\t} while (0)");
			printh("");
			printh("/* struct eventlog_session *session */");
			printh("#define " provider_upper "_EVENTLOG_" event_name "_LOG(__session) \\");
			printh("\tdo { \\");
			printh("\t\tif (" provider_upper "_EVENTLOG_" event_name "_ENABLED(__session)) { \\");
			printh("\t\t\t" provider_upper "_EVENTLOG_" event_name "_LOG_ALWAYS(__session); \\");
			printh("\t\t} \\");
			printh("\t} while (0)");
			printh("");
			printh("#define " provider_upper "_EVENTLOG_" event_name "_FORMAT \"" events[i, "format"] "\"");
			printh("");
		} else {
			# Find the struct definition for this event
			struct_idx = 0;
			for (j = 1; j <= nstructs; j++) {
				if (structs[j, "name"] == struct_name) {
					struct_idx = j;
					break;
				}
			}

			if (struct_idx == 0) {
				die("Struct " struct_name " not found for event " event_name);
			}

			# Generate _LOG_ALWAYS and _LOG macros
			field_count = structs[struct_idx, "field_count"];
			has_varlen = (structs[struct_idx, "has_varlen"] == 1);
			varlen_idx = has_varlen ? structs[struct_idx, "varlen_field_idx"] : 0;

			# For varlen events, the last parameter is a pointer to a user-supplied
			# source array of elements; the count is taken from the count_field
			# parameter already in the signature. We do not append an extra count
			# parameter -- the count is whichever scalar field the schema named.

			# Build parameter list (without types) and comment list (with types)
			# Use __ prefix for all parameters to avoid collisions with struct field names
			param_list = "__session";
			# Comment uses non-prefixed names for readability
			param_comment = "struct eventlog_session *session";
			struct_type_name = provider_lower "_eventlog_" tolower(struct_name);

			for (j = 1; j <= field_count; j++) {
				field_name = structs[struct_idx, "field", j, "name"];
				field_type = structs[struct_idx, "field", j, "type"];

				# Add to parameter list with __ prefix
				param_list = param_list ", __" field_name;
				# Comment uses non-prefixed names for readability
				if (structs[struct_idx, "field", j, "is_varlen"] == 1) {
					param_comment = param_comment ", const " field_type " *" field_name;
				} else {
					param_comment = param_comment ", " field_type " " field_name;
				}
			}

			# Generate _LOG_ALWAYS macro (does the actual logging)
			# Use __ prefixed parameter names to avoid collisions with struct field names
			# Check if any field is char[N] (requires strncpy, not direct assignment)
			has_char_array = 0;
			for (j = 1; j <= field_count; j++) {
				field_type = structs[struct_idx, "field", j, "type"];
				if (match(field_type, /^char\[[0-9]+\]$/)) {
					has_char_array = 1;
					break;
				}
			}

			printh("/* " param_comment " */");
			printh("#define " provider_upper "_EVENTLOG_" event_name "_LOG_ALWAYS(" param_list ") \\");
			printh("\tdo { \\");
			if (has_varlen) {
				# Build a 2-element iovec: [0] = the fixed head on the
				# stack, [1] = the caller's source array. The framework's
				# gather write path copies directly into the subscriber
				# ring buffer, avoiding the pre-copy and the worst-case
				# stack footprint of a composite struct.
				varlen_field_name = structs[struct_idx, "field", varlen_idx, "name"];
				varlen_elem_type = structs[struct_idx, "field", varlen_idx, "type"];
				varlen_count_name = structs[struct_idx, "field", varlen_idx, "varlen_count"];
				varlen_max_define = provider_upper "_EVENTLOG_" toupper(struct_name) \
				    "_" toupper(varlen_field_name) "_MAX";

				# The struct is __packed so sizeof(__head) is exactly
				# the sum of field bytes -- assigning every field is
				# sufficient to cover all the bytes that get written to
				# the iovec (no trailing pad, no inter-field pad).  Char
				# arrays are filled by strncpy + an explicit nul at
				# [N-1], which together cover every byte of the array.
				printh("\t\tstruct " struct_type_name " __head; \\");
				printh("\t\tstruct iovec __iov[2]; \\");
				printh("\t\tsize_t __n = (size_t)(__" varlen_count_name "); \\");
				printh("\t\tif (__n > " varlen_max_define ") \\");
				printh("\t\t\t__n = " varlen_max_define "; \\");
				for (j = 1; j < field_count; j++) {
					field_name = structs[struct_idx, "field", j, "name"];
					field_type = structs[struct_idx, "field", j, "type"];
					if (match(field_type, /^char\[[0-9]+\]$/)) {
						printh("\t\tstrncpy(__head." field_name ", (__" field_name ") ? (__" field_name ") : \"\", sizeof(__head." field_name ") - 1); \\");
						printh("\t\t__head." field_name "[sizeof(__head." field_name ") - 1] = '\\0'; \\");
					} else if (field_name == varlen_count_name) {
						# Overwrite the count with the clamped value so
						# the wire layout matches what we actually pack.
						printh("\t\t__head." field_name " = __n; \\");
					} else {
						printh("\t\t__head." field_name " = (__" field_name "); \\");
					}
				}
				printh("\t\t__iov[0].iov_base = (void *)&__head; \\");
				printh("\t\t__iov[0].iov_len = sizeof(__head); \\");
				printh("\t\t__iov[1].iov_base = __DECONST(void *, (__" varlen_field_name ")); \\");
				printh("\t\t__iov[1].iov_len = __n * sizeof(" varlen_elem_type "); \\");
				printh("\t\teventlog_event_write_gather(__session, " events[i, "id"] ", " level_enum ", (" keyword_flags "), __iov, 2); \\");
			} else if (has_char_array) {
				# As above: __packed struct + per-field assignment + the
				# strncpy/nul pair on char arrays covers every byte.
				printh("\t\tstruct " struct_type_name " __evt; \\");
				for (j = 1; j <= field_count; j++) {
					field_name = structs[struct_idx, "field", j, "name"];
					field_type = structs[struct_idx, "field", j, "type"];
					if (match(field_type, /^char\[[0-9]+\]$/)) {
						printh("\t\tstrncpy(__evt." field_name ", (__" field_name ") ? (__" field_name ") : \"\", sizeof(__evt." field_name ") - 1); \\");
						printh("\t\t__evt." field_name "[sizeof(__evt." field_name ") - 1] = '\\0'; \\");
					} else {
						printh("\t\t__evt." field_name " = (__" field_name "); \\");
					}
				}
				printh("\t\teventlog_event_write(__session, " events[i, "id"] ", " level_enum ", (" keyword_flags "), &__evt, sizeof(__evt)); \\");
			} else {
				printh("\t\tstruct " struct_type_name " __evt = { \\");
				for (j = 1; j <= field_count; j++) {
					field_name = structs[struct_idx, "field", j, "name"];
					if (j < field_count) {
						printh("\t\t\t." field_name " = (__" field_name "), \\");
					} else {
						printh("\t\t\t." field_name " = (__" field_name ") \\");
					}
				}
				printh("\t\t}; \\");
				printh("\t\teventlog_event_write(__session, " events[i, "id"] ", " level_enum ", (" keyword_flags "), &__evt, sizeof(__evt)); \\");
			}
			printh("\t} while (0)");
			printh("");

			# Generate _LOG macro (checks enabled and calls _LOG_ALWAYS)
			# Use same __ prefixed parameters, pass directly to _LOG_ALWAYS
			printh("/* " param_comment " */");
			printh("#define " provider_upper "_EVENTLOG_" event_name "_LOG(" param_list ") \\");
			printh("\tdo { \\");
			printh("\t\tif (" provider_upper "_EVENTLOG_" event_name "_ENABLED(__session)) { \\");
			printh("\t\t\t" provider_upper "_EVENTLOG_" event_name "_LOG_ALWAYS(" param_list "); \\");
			printh("\t\t} \\");
			printh("\t} while (0)");
			printh("");
		}
		}

		# SESSION_END/SESSION_CREATE use fixed IDs from eventlog.h - no producer defines needed
	}

	printh("#endif /* _" provider_upper "_EVENTLOG_H_ */");
}

