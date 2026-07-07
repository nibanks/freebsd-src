#!/usr/bin/awk -f

#
# Copyright (c) 2026 Netflix, Inc.
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Script to generate event log header file from schema file.
#
# usage: eventlog_gen.awk <schema.src> -h  (generate producer header for kernel)
#        eventlog_gen.awk <schema.src> -c  (generate consumer header for userland)

function usage()
{
	print "usage: eventlog_gen.awk <schema.src> [<schema.src> ...] -h|-c|-M [-o <outfile>]";
	print "  -h  Generate producer header (for event producers)";
	print "  -c  Generate consumer header (for userland tools consuming events)";
	print "  -M  Generate aggregate consumer header routing across all schemas (-o required)";
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
	opt_c = 0;
	opt_m = 0;
	outfile = "";
	mode = "";  # "producer", "consumer", or "master"
	collecting_struct = 0;
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
			mode = "producer";
			ARGV[i] = "";
		} else if (ARGV[i] == "-c") {
			opt_c = 1;
			mode = "consumer";
			ARGV[i] = "";
		} else if (ARGV[i] == "-M") {
			opt_m = 1;
			mode = "master";
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

	# Exactly one mode and at least one schema file are required
	if (opt_h + opt_c + opt_m != 1)
		usage();
	if (nfiles < 1)
		usage();
	# Master mode writes a fixed aggregate header, so -o is required
	if (mode == "master" && outfile == "")
		usage();

	# Determine output file name (will be set in END after PROVIDER is parsed)
	# hfile is initialized above and will be set in END block

	# Generate header file header (will be done in END after provider is known)
}

# Master mode: collect the provider name from each schema and skip all other
# parsing.  The aggregate routing header is emitted in END.
mode == "master" {
	if ($0 ~ /^[ \t]*PROVIDER/ && !(FILENAME in master_seen)) {
		mline = $0;
		sub(/^[ \t]+/, "", mline);
		gsub(/[ \t]+/, " ", mline);
		mn = split(mline, mf, " ");
		if (mn >= 2) {
			check_provider_name(mf[2], FILENAME);
			master_n++;
			master_providers[master_n] = tolower(mf[2]);
			master_seen[FILENAME] = 1;
		}
	}
	next;
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
	# provider (and optional outdir).  Filename depends on producer/consumer.
	if (outfile != "") {
		hfile = outfile;
	} else if (outdir != "") {
		if (mode == "consumer") {
			hfile = outdir "/" provider_lower "_eventlog_consumer.h";
		} else {
			hfile = outdir "/" provider_lower "_eventlog.h";
		}
	} else {
		if (mode == "consumer") {
			hfile = provider_lower "_eventlog_consumer.h";
		} else {
			hfile = provider_lower "_eventlog.h";
		}
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

# Emit the aggregate consumer header that routes by provider name across all
# schemas seen in master mode.  Output goes to the -o file (hfile).
function gen_master(   i, j, tmp, p)
{
	hfile = outfile;

	# Sort provider names for deterministic output.
	for (i = 1; i <= master_n; i++) {
		for (j = i + 1; j <= master_n; j++) {
			if (master_providers[j] < master_providers[i]) {
				tmp = master_providers[i];
				master_providers[i] = master_providers[j];
				master_providers[j] = tmp;
			}
		}
	}

	printh("/* Auto-generated consumer header - includes all provider consumer headers */");
	printh("#ifndef _EVENTLOG_CONSUMER_H_");
	printh("#define _EVENTLOG_CONSUMER_H_");
	printh("");
	printh("#include <sys/eventlog.h>");
	for (i = 1; i <= master_n; i++)
		printh("#include \"" master_providers[i] "_eventlog_consumer.h\"");
	printh("");
	printh("/* Check if event is SESSION_END (fixed ID, all providers). Include sys/eventlog.h for EVENTLOG_SESSION_END_ID. */");
	printh("static inline bool");
	printh("eventlog_is_session_end(const char *provider_name, uint32_t event_id)");
	printh("{");
	printh("\t(void)provider_name;");
	printh("\treturn event_id == EVENTLOG_SESSION_END_ID;");
	printh("}");
	printh("");
	printh("/* Master formatting function that routes to per-provider formatters */");
	printh("static inline int");
	printh("eventlog_format_payload(const char *provider_name, const void *payload, size_t payload_size, uint32_t event_id, char *buf, size_t bufsize)");
	printh("{");
	for (i = 1; i <= master_n; i++) {
		p = master_providers[i];
		printh("\tif (strcmp(provider_name, \"" p "\") == 0)");
		printh("\t\treturn " p "_eventlog_format_payload(payload, payload_size, event_id, buf, bufsize);");
	}
	printh("\treturn snprintf(buf, bufsize, \"[UNKNOWN_PROVIDER:%s]\", provider_name);");
	printh("}");
	printh("");
	printh("/* Master event ID to name lookup (routes to per-provider lookups) */");
	printh("static inline const char *");
	printh("eventlog_event_id_to_name(const char *provider_name, uint32_t event_id)");
	printh("{");
	printh("\tif (event_id == EVENTLOG_SESSION_END_ID)");
	printh("\t\treturn \"SESSION_END\";");
	for (i = 1; i <= master_n; i++) {
		p = master_providers[i];
		printh("\tif (strcmp(provider_name, \"" p "\") == 0)");
		printh("\t\treturn " p "_eventlog_event_id_to_name(event_id);");
	}
	printh("\treturn NULL;");
	printh("}");
	printh("");
	printh("/* Master keyword name to bitmask lookup (routes to per-provider lookups) */");
	printh("static inline uint32_t");
	printh("eventlog_keyword_from_string(const char *provider_name, const char *name)");
	printh("{");
	for (i = 1; i <= master_n; i++) {
		p = master_providers[i];
		printh("\tif (strcmp(provider_name, \"" p "\") == 0)");
		printh("\t\treturn " p "_eventlog_keyword_from_string(name);");
	}
	printh("\treturn (0);");
	printh("}");
	printh("");
	printh("#endif /* _EVENTLOG_CONSUMER_H_ */");
}

END {
	# A fatal parse error (e.g. provider/file-name mismatch) set parse_error
	# and exited mid-rule; awk still runs END, so bail before producing any
	# output.  The bare exit preserves the status already set by exit 1.
	if (parse_error)
		exit;

	# Master mode: emit the aggregate routing header and stop.  Guard on
	# outfile so a usage() exit from BEGIN doesn't fall through to writing an
	# empty filename; bare exit preserves any status already set by BEGIN.
	if (mode == "master") {
		if (outfile != "")
			gen_master();
		exit;
	}

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
	# SESSION_END has no payload - uses NONE struct
	# Add reserved events with fixed IDs (UINT32_MAX-1, UINT32_MAX) if not in schema
	has_session_create_evt = 0;
	has_session_end_evt = 0;
	for (ei = 1; ei <= nevents; ei++) {
		if (events[ei, "name"] == "SESSION_CREATE") has_session_create_evt = 1;
		if (events[ei, "name"] == "SESSION_END") has_session_end_evt = 1;
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

	if (hfile == "" && outfile != "") {
		hfile = outfile;
	}
	if (hfile == "") {
		provider_lower = tolower(provider);
		# If outdir was provided via -v outdir=..., use it
		if (outdir != "") {
			if (mode == "consumer") {
				hfile = outdir "/" provider_lower "_eventlog_consumer.h";
			} else {
				hfile = outdir "/" provider_lower "_eventlog.h";
			}
		} else {
			if (mode == "consumer") {
				hfile = provider_lower "_eventlog_consumer.h";
			} else {
				hfile = provider_lower "_eventlog.h";
			}
		}
	}

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
	# libkern (strncpy, bzero) only for kernel producer; consumer uses string.h
	if (needs_string && mode == "producer")
		printh("#include <sys/libkern.h>");
	# struct iovec for the gather write path (producer-only).
	if (needs_iovec && mode == "producer")
		printh("#include <sys/uio.h>");
	printh("");

	# Generate provider instance and macros at the top
	provider_upper = toupper(provider);
	provider_lower = tolower(provider);

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
		# For structs with a VARLEN trailing array, force struct alignment
		# (and therefore sizeof) to be a multiple of alignof(elem_type) so
		# the trailing array starts on an aligned offset. Without this, a
		# head that ends at e.g. offset 12 followed by a uint64[] trailer
		# would produce an unaligned cast (-Wcast-align) and, worse, a
		# real unaligned access on strict-alignment architectures.
		struct_align = 0;
		if (structs[i, "has_varlen"] == 1) {
			vidx = structs[i, "varlen_field_idx"];
			struct_align = get_type_size(structs[i, "field", vidx, "type"]);
		}
		if (struct_align > 0) {
			printh("struct __aligned(" struct_align ") " \
			    provider_lower "_eventlog_" tolower(struct_name) " {");
		} else {
			printh("struct " provider_lower "_eventlog_" tolower(struct_name) " {");
		}
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
		printh("};");
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
			printh(" * Read the trailing " vname "[] array from a " struct_name " wire payload.");
			printh(" * Returns a pointer to the first element, or NULL if the payload is too");
			printh(" * small to hold the claimed count. Callers should use evt->" vcount);
			printh(" * (already bounded to " vmax_define ") as the element count.");
			printh(" */");
			printh("static inline const " vtype " *");
			printh(provider_lower "_eventlog_" tolower(struct_name) "_" tolower(vname) \
			    "(const struct " provider_lower "_eventlog_" tolower(struct_name) " *evt, size_t payload_size)");
			printh("{");
			printh("\tsize_t __head = sizeof(*evt);");
			printh("\tsize_t __n = (size_t)evt->" vcount ";");
			printh("\tif (__n > " vmax_define ")");
			printh("\t\treturn NULL;");
			printh("\tif (payload_size < __head + __n * sizeof(" vtype "))");
			printh("\t\treturn NULL;");
			# Cast via const void * to silence -Wcast-align. The struct
			# definition above carries __aligned(sizeof(" vtype ")) so the
			# trailing array is guaranteed to start on an aligned offset.
			printh("\treturn (const " vtype " *)(const void *)((const char *)evt + __head);");
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

	# Generate enum constant definitions (needed for both modes)
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

	# Generate flag constant definitions (needed for both modes)
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

	# Generate event ID constants (both modes)
	printh("/* Event ID constants */");
	for (i = 1; i <= nevents; i++) {
		printh("#define\t" toupper(provider) "_EVENTLOG_" events[i, "name"] "_ID\t" events[i, "id"]);
	}
	printh("");

	# Generate event definitions (producer mode only)
	if (mode == "producer") {
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

		# Parse keywords into keyword_flags
		keywords_str = events[i, "keywords"];
		keyword_flags = "";
		# Only use keywords explicitly defined in schema
		for (j = 1; j <= nkeywords; j++) {
			keyword_name = keywords[j, "name"];
			if (index(keywords_str, keyword_name) > 0)
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

		# Generate enabled macro - uses session effective_level/effective_keywords
		printh("#define " provider_upper "_EVENTLOG_" event_name "_ENABLED(__session) \\");
		printh("\t((__session != NULL) && \\");
		printh("\t ((__session)->effective_level >= " level_enum ") && \\");
		printh("\t (((__session)->effective_keywords & (" keyword_flags ")) != 0))");
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

				# All declarations first so the expansion is valid in a
				# nested block in strict C modes.
				printh("\t\tstruct " struct_type_name " __head; \\");
				printh("\t\tstruct iovec __iov[2]; \\");
				printh("\t\tsize_t __n = (size_t)(__" varlen_count_name "); \\");
				printh("\t\tif (__n > " varlen_max_define ") \\");
				printh("\t\t\t__n = " varlen_max_define "; \\");
				if (has_char_array) {
					printh("\t\tbzero(&__head, sizeof(__head)); \\");
				}
				# Assign head fields (all fields except the varlen one).
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
				printh("\t\tstruct " struct_type_name " __evt; \\");
				printh("\t\tbzero(&__evt, sizeof(__evt)); \\");
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
			# Generate format string constant - for producer mode, just store the original format string
			# The consumer mode will convert %N placeholders to printf format specifiers
			printh("#define " provider_upper "_EVENTLOG_" event_name "_FORMAT \"" events[i, "format"] "\"");
			printh("");
		}
		}

		# SESSION_END/SESSION_CREATE use fixed IDs from eventlog.h - no producer defines needed
	}

	# Generate enum/flag lookup functions for userland (consumer mode only)
	if (mode == "consumer") {
		# SESSION_END/SESSION_CREATE use fixed EVENTLOG_SESSION_END_ID, EVENTLOG_SESSION_CREATE_ID from eventlog.h
		printh("#include <stdio.h>");
		printh("#include <string.h>");
		# Check if we need arpa/inet.h and sys/socket.h for IP address formatting or ntohs
		needs_inet_header = 0;
		for (i = 1; i <= nstructs; i++) {
			field_count = structs[i, "field_count"];
			for (j = 1; j <= field_count; j++) {
				field_type = structs[i, "field", j, "type"];
				if (field_type == "in_addr_t" || field_type == "struct in_addr" || field_type == "in6_addr_t" || field_type == "struct in6_addr") {
					needs_inet_header = 1;
					break;
				}
				if (structs[i, "field", j, "ntohs"] == 1) {
					needs_inet_header = 1;
					break;
				}
			}
			if (needs_inet_header)
				break;
		}
		if (needs_inet_header) {
			printh("#include <sys/socket.h>");
			printh("#include <arpa/inet.h>");
			printh("#include <netinet/in.h>");
		}
		printh("");
		printh("/*");
		printh(" * Format string constants");
		printh(" */");
		printh("");
		# Format string constants are generated in the formatting function below
		# where %N placeholders are converted to printf format specifiers
		printh("");
		printh("/*");
		printh(" * Enum and flag lookup functions");
		printh(" * These functions convert numeric enum/flag values to strings");
		printh(" */");
		printh("");

	# Generate enum lookup functions
	for (i = 1; i <= nenums; i++) {
		enum_name = enums[i, "name"];
		value_count = enums[i, "value_count"];
		printh("/*");
		printh(" * Lookup enum value for " enum_name);
		printh(" * Returns string representation or NULL if not found");
		printh(" */");
		printh("static inline const char *");
		printh(provider_lower "_eventlog_enum_" tolower(enum_name) "_to_string(uint32_t value)");
		printh("{");
		printh("\tswitch (value) {");
		for (j = 1; j <= value_count; j++) {
			value_num = enums[i, "value", j, "num"];
			value_name = enums[i, "value", j, "name"];
			printh("\tcase " value_num ":");
			printh("\t\treturn \"" value_name "\";");
		}
		printh("\tdefault:");
		printh("\t\treturn NULL;");
		printh("\t}");
		printh("}");
		printh("");
	}

	# Generate flag lookup functions
	for (i = 1; i <= nflags; i++) {
		flag_name = flags[i, "name"];
		value_count = flags[i, "value_count"];
		printh("/*");
		printh(" * Lookup flag value for " flag_name);
		printh(" * Returns string representation of combined flags or NULL if empty");
		printh(" * Format: \"FLAG1|FLAG2|...\"");
		printh(" */");
		printh("static inline int");
		printh(provider_lower "_eventlog_flag_" tolower(flag_name) "_to_string(uint32_t value, char *buf, size_t bufsize)");
		printh("{");
		printh("\tint len = 0;");
		printh("\tint first = 1;");
		printh("");
		printh("\tif (buf == NULL || bufsize == 0)");
		printh("\t\treturn -1;");
		printh("");
		printh("\tbuf[0] = '\\0';");
		printh("");
		printh("\tif (value == 0)");
		printh("\t\treturn 0;");
		printh("");
		# Generate flag bit checks
		for (j = 1; j <= value_count; j++) {
			value_num = flags[i, "value", j, "num"];
			value_name = flags[i, "value", j, "name"];
			printh("\tif (value & " value_num ") {");
			printh("\t\tif (!first && len < (int)bufsize - 1) {");
			printh("\t\t\tbuf[len++] = '|';");
			printh("\t\t}");
			printh("\t\tfirst = 0;");
			printh("\t\tif (len < (int)bufsize - 1) {");
			printh("\t\t\tint n = snprintf(buf + len, bufsize - len, \"" value_name "\");");
			printh("\t\t\tif (n > 0 && n < (int)(bufsize - len))");
			printh("\t\t\t\tlen += n;");
			printh("\t\t}");
			printh("\t}");
		}
		printh("");
		printh("\tbuf[len] = '\\0';");
		printh("\treturn len;");
		printh("}");
		printh("");
	}

	# Generate keyword name-to-bitmask lookup function
	printh("/*");
	printh(" * Convert a keyword name string to its bitmask value.");
	printh(" * Returns the keyword bitmask, or 0 if the name is not recognized.");
	printh(" */");
	printh("static inline uint32_t");
	printh(provider_lower "_eventlog_keyword_from_string(const char *name)");
	printh("{");
	for (i = 1; i <= nkeywords; i++) {
		kw_name = keywords[i, "name"];
		# Resolve the define value we already emitted
		define_name = toupper(provider) "_EVENTLOG_KEYWORD_" kw_name;
		printh("\tif (strcasecmp(name, \"" kw_name "\") == 0)");
		printh("\t\treturn (" define_name ");");
	}
	printh("\treturn (0);");
	printh("}");
	printh("");

	# Generate formatting functions for userland (elog utility)
	printh("/*");
	printh(" * Userland formatting functions for event log parsing");
	printh(" * These functions format event data into human-readable strings");
	printh(" */");
	printh("");


	# Generate per-event formatting functions
	for (i = 1; i <= nevents; i++) {
		event_name = events[i, "name"];
		struct_name = events[i, "struct"];
		format_str = events[i, "format"];
		event_id = events[i, "id"];

		if (struct_name == "NONE") {
			# No-payload event: format function takes no evt argument
			printf_format_escaped = format_str;
			gsub(/\\/, "\\\\", printf_format_escaped);
			gsub(/"/, "\\\"", printf_format_escaped);
			printh("#define " provider_upper "_EVENTLOG_" event_name "_FORMAT \"" printf_format_escaped "\"");
			printh("");
			printh("/*");
			printh(" * Format " provider_upper " " event_name " event to string");
			printh(" * Returns number of characters written (excluding null terminator),");
			printh(" * or -1 on error");
			printh(" */");
			printh("static inline int");
			printh(provider_lower "_eventlog_format_" tolower(event_name) "(char *buf, size_t bufsize)");
			printh("{");
			printh("\treturn snprintf(buf, bufsize, " provider_upper "_EVENTLOG_" event_name "_FORMAT);");
			printh("}");
			printh("");
			continue;
		}

		# Find the struct definition
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

		struct_type_name = provider_lower "_eventlog_" tolower(struct_name);
		field_count = structs[struct_idx, "field_count"];

		# Parse format string to find positional placeholders (%1, %2, etc.)
		# and build mapping from placeholder index to field index
		placeholder_count = 0;
		delete placeholder_to_field;
		# Extract all %N placeholders from format string
		format_copy = format_str;
		while (match(format_copy, /%[0-9]+/)) {
			placeholder_num = substr(format_copy, RSTART + 1, RLENGTH - 1) + 0;  # Extract number, convert to int
			if (placeholder_num > 0 && placeholder_num <= field_count) {
				# Varlen fields cannot be referenced from a format string --
				# there is no single printf specifier for a variable-length
				# array. Use the generated accessor helper at runtime instead.
				if (structs[struct_idx, "field", placeholder_num, "is_varlen"] == 1) {
					die("Event " event_name " format references varlen field (%s); use the generated accessor helper instead", \
					    structs[struct_idx, "field", placeholder_num, "name"]);
				}
				placeholder_count++;
				placeholder_to_field[placeholder_count] = placeholder_num;
			} else {
				die("Invalid placeholder %" placeholder_num " in format string for event " event_name " (field count is " field_count ")");
			}
			format_copy = substr(format_copy, RSTART + RLENGTH);
		}

		# If no placeholders found, assume old-style format (all fields in order)
		# but only when the format string contains % (e.g. "Value: %1"). Events with
		# no format args (e.g. "Timer canceled", "Session ended") use no-args path.
		# Skip varlen fields -- they cannot be printf-formatted inline.
		if (placeholder_count == 0 && index(format_str, "%") > 0 && event_name != "SESSION_END") {
			for (j = 1; j <= field_count; j++) {
				if (structs[struct_idx, "field", j, "is_varlen"] == 1)
					continue;
				placeholder_count++;
				placeholder_to_field[placeholder_count] = j;
			}
		}

		# Build printf format string by replacing %N placeholders with actual format specifiers
		# (Do this early so we can generate the format constant before the function)
		printf_format = format_str;
		# Process placeholders in reverse order to avoid replacing parts of already-replaced placeholders
		# Build a sorted list of unique field indices
		delete field_indices;
		field_idx_count = 0;
		for (j = 1; j <= placeholder_count; j++) {
			field_idx = placeholder_to_field[j];
			found = 0;
			for (k = 1; k <= field_idx_count; k++) {
				if (field_indices[k] == field_idx) {
					found = 1;
					break;
				}
			}
			if (!found) {
				field_idx_count++;
				field_indices[field_idx_count] = field_idx;
			}
		}
		# Sort field indices in descending order for replacement
		for (j = 1; j < field_idx_count; j++) {
			for (k = j + 1; k <= field_idx_count; k++) {
				if (field_indices[j] < field_indices[k]) {
					tmp = field_indices[j];
					field_indices[j] = field_indices[k];
					field_indices[k] = tmp;
				}
			}
		}
		# Replace placeholders with format specifiers (largest first to avoid partial matches)
		for (j = 1; j <= field_idx_count; j++) {
			field_idx = field_indices[j];
			field_type = structs[struct_idx, "field", field_idx, "type"];
			enum_type = structs[struct_idx, "field", field_idx, "enum_type"];
			flag_type = structs[struct_idx, "field", field_idx, "flag_type"];
			hex_format = structs[struct_idx, "field", field_idx, "hex_format"];
			format_spec = get_printf_format(field_type, enum_type, flag_type, hex_format);
			# Add "0x" prefix for hex fields
			if (hex_format) {
				format_spec = "0x" format_spec;
			}
			# Replace %N with the format specifier
			placeholder_str = "%" field_idx;
			gsub(placeholder_str, format_spec, printf_format);
		}

		# Generate the format string constant with printf specifiers (before the function)
		# Escape quotes and backslashes in the format string for C string literal
		# Note: % signs are preserved as-is (they're part of printf format specifiers)
		printf_format_escaped = printf_format;
		gsub(/\\/, "\\\\", printf_format_escaped);  # Escape backslashes
		gsub(/"/, "\\\"", printf_format_escaped);  # Escape quotes
		printh("#define " provider_upper "_EVENTLOG_" event_name "_FORMAT \"" printf_format_escaped "\"");
		printh("");

		# Generate formatting function for this event
		printh("/*");
		printh(" * Format " provider_upper " " event_name " event to string");
		printh(" * Returns number of characters written (excluding null terminator),");
		printh(" * or -1 on error");
		printh(" */");
		printh("static inline int");
		printh(provider_lower "_eventlog_format_" tolower(event_name) "(const struct " struct_type_name " *evt, size_t payload_size, char *buf, size_t bufsize)");
		printh("{");
		printh("\tint ret;");
		printh("\t(void)payload_size; /* may be unused for fixed-size events */");
		printh("");

		# Determine which fields are actually used in the format string
		delete fields_used;
		for (j = 1; j <= placeholder_count; j++) {
			field_idx = placeholder_to_field[j];
			fields_used[field_idx] = 1;
		}

		# Generate enum/flag/IP lookups only for fields that are used
		needs_lookup = 0;
		for (j = 1; j <= field_count; j++) {
			if (!fields_used[j])
				continue;
			field_type = structs[struct_idx, "field", j, "type"];
			if (structs[struct_idx, "field", j, "enum_type"] != "" || structs[struct_idx, "field", j, "flag_type"] != "") {
				needs_lookup = 1;
			}
			if (field_type == "in_addr_t" || field_type == "struct in_addr" || field_type == "in6_addr_t" || field_type == "struct in6_addr") {
				needs_lookup = 1;
			}
		}

		# Generate enum/flag/IP lookups and convert to strings (only for used fields)
		for (j = 1; j <= field_count; j++) {
			if (!fields_used[j])
				continue;
			field_name = structs[struct_idx, "field", j, "name"];
			field_type = structs[struct_idx, "field", j, "type"];
			enum_type = structs[struct_idx, "field", j, "enum_type"];
			flag_type = structs[struct_idx, "field", j, "flag_type"];

			if (enum_type != "") {
				printh("\tconst char *" field_name "_str = " provider_lower "_eventlog_enum_" tolower(enum_type) "_to_string(evt->" field_name ");");
				printh("\tchar " field_name "_val[32];");
				printh("\tif (" field_name "_str == NULL)");
				printh("\t\tsnprintf(" field_name "_val, sizeof(" field_name "_val), \"%u\", evt->" field_name ");");
			} else if (flag_type != "") {
				printh("\tchar " field_name "_buf[128];");
				printh("\tint " field_name "_len = " provider_lower "_eventlog_flag_" tolower(flag_type) "_to_string(evt->" field_name ", " field_name "_buf, sizeof(" field_name "_buf));");
				printh("\tchar " field_name "_val[32];");
				printh("\tif (" field_name "_len == 0)");
				printh("\t\tsnprintf(" field_name "_val, sizeof(" field_name "_val), \"%u\", evt->" field_name ");");
			} else if (field_type == "in_addr_t" || field_type == "struct in_addr") {
				printh("\tchar " field_name "_str[INET_ADDRSTRLEN];");
				printh("\tif (inet_ntop(AF_INET, &evt->" field_name ", " field_name "_str, sizeof(" field_name "_str)) == NULL)");
				printh("\t\tstrcpy(" field_name "_str, \"<invalid>\");");
			} else if (field_type == "in6_addr_t" || field_type == "struct in6_addr") {
				printh("\tchar " field_name "_str[INET6_ADDRSTRLEN];");
				printh("\tif (inet_ntop(AF_INET6, &evt->" field_name ", " field_name "_str, sizeof(" field_name "_str)) == NULL)");
				printh("\t\tstrcpy(" field_name "_str, \"<invalid>\");");
			}
		}

		if (needs_lookup) {
			printh("");
		}

		# Note: Format string constant was already generated above before the function
		# printf_format variable is already set with the converted format string

		# Build argument list in the order placeholders appear in format string
		arg_list = "";
		for (j = 1; j <= placeholder_count; j++) {
			field_idx = placeholder_to_field[j];
			field_name = structs[struct_idx, "field", field_idx, "name"];
			field_type = structs[struct_idx, "field", field_idx, "type"];
			enum_type = structs[struct_idx, "field", field_idx, "enum_type"];
			flag_type = structs[struct_idx, "field", field_idx, "flag_type"];

			if (arg_list != "")
				arg_list = arg_list ", ";

			if (enum_type != "") {
				# Use enum string if available, otherwise use formatted number
				arg_list = arg_list "(" field_name "_str != NULL ? " field_name "_str : " field_name "_val)";
			} else if (flag_type != "") {
				# Use flag string if available, otherwise use formatted number
				arg_list = arg_list "(" field_name "_len > 0 ? " field_name "_buf : " field_name "_val)";
			} else if (field_type == "in_addr_t" || field_type == "struct in_addr") {
				# Use formatted IP address string
				arg_list = arg_list field_name "_str";
			} else if (field_type == "in6_addr_t" || field_type == "struct in6_addr") {
				# Use formatted IPv6 address string (works with or without INET6)
				arg_list = arg_list field_name "_str";
			} else if (structs[struct_idx, "field", field_idx, "ntohs"] == 1) {
				# Network-to-host byte order conversion
				arg_list = arg_list "ntohs(evt->" field_name ")";
			} else {
				# Direct field access
				arg_list = arg_list "evt->" field_name;
			}
		}

		# Handle empty format strings (no placeholders)
		# Note: Format string constant was already generated above before the function
		if (placeholder_count > 0) {
			printh("\tret = snprintf(buf, bufsize, " provider_upper "_EVENTLOG_" event_name "_FORMAT, " arg_list ");");
		} else {
			printh("\t(void)evt; /* Unused for empty format */");
			printh("\tret = snprintf(buf, bufsize, " provider_upper "_EVENTLOG_" event_name "_FORMAT);");
		}
		printh("\treturn ret;");
		printh("}");
		printh("");
	}

	# Generate generic formatting function that formats payload based on event ID
	printh("/*");
	printh(" * Format an event payload to string");
	printh(" * payload: Pointer to event payload data");
	printh(" * payload_size: Size of the payload");
	printh(" * event_id: Event ID to determine which formatter to use");
	printh(" * buf: Output buffer");
	printh(" * bufsize: Size of output buffer");
	printh(" * Returns number of characters written, or -1 on error");
	printh(" */");
	printh("static inline int");
	printh(provider_lower "_eventlog_format_payload(const void *payload, size_t payload_size, uint32_t event_id, char *buf, size_t bufsize)");
	printh("{");
		printh("\t(void)payload_size; /* May be unused depending on event */");
		printh("\tif (buf == NULL || bufsize == 0)");
		printh("\t\treturn -1;");
		printh("\tif (payload == NULL && payload_size > 0)");
		printh("\t\treturn -1;");
		printh("\t");
		printh("\tswitch (event_id) {");

	for (i = 1; i <= nevents; i++) {
		event_name = events[i, "name"];
		struct_name = events[i, "struct"];
		event_id = events[i, "id"];

		printh("\tcase " event_id ":");
		if (struct_name == "NONE") {
			printh("\t\treturn " provider_lower "_eventlog_format_" tolower(event_name) "(buf, bufsize);");
		} else {
			struct_type_name = provider_lower "_eventlog_" tolower(struct_name);
			if (event_name == "SESSION_CREATE") {
				printh("\t\tif (payload_size == 0)");
				printh("\t\t\treturn snprintf(buf, bufsize, \"Session created\");");
			}
			printh("\t\treturn " provider_lower "_eventlog_format_" tolower(event_name) "((const struct " struct_type_name " *)payload, payload_size, buf, bufsize);");
		}
	}

	printh("\tdefault:");
	printh("\t\treturn snprintf(buf, bufsize, \"[UNKNOWN_EVENT_ID:%u]\", event_id);");
	printh("\t}");
	printh("}");
		printh("");

	# Generate event ID to name lookup function
	printh("/*");
	printh(" * Map event ID to event name string");
	printh(" * Returns event name (e.g. \"IN\", \"OUT\") or NULL if unknown");
	printh(" */");
	printh("static inline const char *");
	printh(provider_lower "_eventlog_event_id_to_name(uint32_t event_id)");
	printh("{");
	printh("\tswitch (event_id) {");

	for (i = 1; i <= nevents; i++) {
		event_name = events[i, "name"];
		event_id = events[i, "id"];
		printh("\tcase " event_id ": return \"" event_name "\";");
	}

	printh("\tdefault: return NULL;");
	printh("\t}");
	printh("}");
	printh("");
	}

	printh("#endif /* _" provider_upper "_EVENTLOG_H_ */");
}

