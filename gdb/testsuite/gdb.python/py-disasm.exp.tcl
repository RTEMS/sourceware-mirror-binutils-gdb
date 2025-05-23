# Copyright (C) 2021-2025 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This file is part of the GDB testsuite.  It validates the Python
# disassembler API.

load_lib gdb-python.exp

require allow_python_tests

standard_testfile py-disasm.c

if { $kind == "obj" } {

    set obj [standard_output_file ${gdb_test_file_name}.o]

    if { [gdb_compile "$srcdir/$subdir/$srcfile" $obj object "debug"] != "" } {
	untested "failed to compile object file [file tail $obj]"
	return -1
    }

    clean_restart $obj

} else {

    if { [prepare_for_testing "failed to prepare" $testfile $srcfile] } {
	return -1
    }

    if { ![runto_main] } {
	fail "can't run to main"
	return 0
    }

}

set pyfile [gdb_remote_download host ${srcdir}/${subdir}/py-disasm.py]

gdb_test "source ${pyfile}" "Python script imported" \
         "import python scripts"

set line [gdb_get_line_number "Break here."]

if { $kind == "obj" } {
    set curr_pc "*unknown*"
    set line [gdb_get_line_number "Break here."]
    gdb_test_multiple "info line $line" "" {
	-re -wrap "starts at address ($hex) \[^\r\n\]*" {
	    set curr_pc $expect_out(1,string)
	    pass $gdb_test_name
	}
    }
} else {
    gdb_breakpoint $line
    gdb_continue_to_breakpoint "Break here."

    set curr_pc [get_valueof "/x" "\$pc" "*unknown*"]
}

gdb_test_no_output "python current_pc = ${curr_pc}"

# The current pc will be something like 0x1234 with no leading zeros.
# However, in the disassembler output addresses are padded with zeros.
# This substitution changes 0x1234 to 0x0*1234, which can then be used
# as a regexp in the disassembler output matching.
set curr_pc_pattern [string replace ${curr_pc} 0 1 "0x0*"]

# Grab the name of the current architecture, this is used in the tests
# patterns below.
set curr_arch [get_python_valueof "gdb.selected_inferior().architecture().name()" "*unknown*"]

# Helper proc that removes all registered disassemblers.
proc py_remove_all_disassemblers {} {
    gdb_test_no_output "python remove_all_python_disassemblers()"
}

# A list of test plans.  Each plan is a list of two elements, the
# first element is the name of a class in py-disasm.py, this is a
# disassembler class.  The second element is a pattern that should be
# matched in the disassembler output.
#
# Each different disassembler tests some different feature of the
# Python disassembler API.
set nop "(nop|nop\t0|[string_to_regexp nop\t{0}])"
set unknown_error_pattern "unknown disassembler error \\(error = -1\\)"
if { $kind == "obj" } {
    set addr_pattern "\r\n   ${curr_pc_pattern} <\[^>\]+>:\\s+"
} else {
    set addr_pattern "\r\n=> ${curr_pc_pattern} <\[^>\]+>:\\s+"
}
set base_pattern "${addr_pattern}${nop}"

# Helper proc to format a Python exception of TYPE with MSG.
proc make_exception_pattern { type msg } {
    return "${::addr_pattern}Python Exception <class '$type'>: $msg\r\n\r\n${::unknown_error_pattern}"
}

# Helper proc to build a pattern for the text Python emits when a
# function argument is missing.  This string changed in Python 3.7 and
# later.  NAME is the parameter name, and POS is its integer position
# in the argument list.
proc missing_arg_pattern { name pos } {
    set pattern_1 "function missing required argument '$name' \\(pos $pos\\)"
    set pattern_2 "Required argument '$name' \\(pos $pos\\) not found"
    return "(?:${pattern_1}|${pattern_2})"
}

set test_plans \
    [list \
	 [list "" "${base_pattern}\r\n.*"] \
	 [list "GlobalNullDisassembler" "${base_pattern}\r\n.*"] \
	 [list "ShowInfoRepr" "${base_pattern}\\s+## <gdb.disassembler.DisassembleInfo address=$hex architecture=\[^>\]+>\r\n.*"] \
	 [list "ShowInfoSubClassRepr" "${base_pattern}\\s+## <MyInfo address=$hex architecture=\[^>\]+>\r\n.*"] \
	 [list "ShowResultRepr" "${base_pattern}\\s+## <gdb.disassembler.DisassemblerResult length=$decimal string=\"\[^\r\n\]+\">\r\n.*"] \
	 [list "ShowResultStr" "${base_pattern}\\s+## ${nop}\r\n.*"] \
	 [list "GlobalPreInfoDisassembler" "${base_pattern}\\s+## ad = $hex, ar = ${curr_arch}\r\n.*"] \
	 [list "GlobalPostInfoDisassembler" "${base_pattern}\\s+## ad = $hex, ar = ${curr_arch}\r\n.*"] \
	 [list "GlobalReadDisassembler" "${base_pattern}\\s+## bytes =( $hex)+\r\n.*"] \
	 [list "GlobalAddrDisassembler" "${base_pattern}\\s+## addr = ${curr_pc_pattern} <\[^>\]+>\r\n.*"] \
	 [list "GdbErrorEarlyDisassembler" "${addr_pattern}GdbError instead of a result\r\n${unknown_error_pattern}"] \
	 [list "RuntimeErrorEarlyDisassembler" "${addr_pattern}Python Exception <class 'RuntimeError'>: RuntimeError instead of a result\r\n\r\n${unknown_error_pattern}"] \
	 [list "GdbErrorLateDisassembler" "${addr_pattern}GdbError after builtin disassembler\r\n${unknown_error_pattern}"] \
	 [list "RuntimeErrorLateDisassembler" "${addr_pattern}Python Exception <class 'RuntimeError'>: RuntimeError after builtin disassembler\r\n\r\n${unknown_error_pattern}"] \
	 [list "MemoryErrorEarlyDisassembler" "${base_pattern}\\s+## AFTER ERROR\r\n.*"] \
	 [list "MemoryErrorLateDisassembler" "${addr_pattern}Cannot access memory at address ${curr_pc_pattern}"] \
	 [list "RethrowMemoryErrorDisassembler" "${addr_pattern}Cannot access memory at address $hex"] \
	 [list "ReadMemoryMemoryErrorDisassembler" "${addr_pattern}Cannot access memory at address ${curr_pc_pattern}"] \
	 [list "ReadMemoryGdbErrorDisassembler" "${addr_pattern}read_memory raised GdbError\r\n${unknown_error_pattern}"] \
	 [list "ReadMemoryRuntimeErrorDisassembler" \
	      [make_exception_pattern "RuntimeError" \
		   "read_memory raised RuntimeError"]] \
	 [list "ReadMemoryCaughtMemoryErrorDisassembler" "${addr_pattern}${nop}\r\n.*"] \
	 [list "ReadMemoryCaughtGdbErrorDisassembler" "${addr_pattern}${nop}\r\n.*"] \
	 [list "ReadMemoryCaughtRuntimeErrorDisassembler" "${addr_pattern}${nop}\r\n.*"] \
	 [list "MemorySourceNotABufferDisassembler" \
	      [make_exception_pattern "TypeError" \
		   "Result from read_memory is not a buffer"]] \
	 [list "MemorySourceBufferTooLongDisassembler" \
	      [make_exception_pattern "ValueError" \
		   "Buffer returned from read_memory is sized $decimal instead of the expected $decimal"]] \
	 [list "ResultOfWrongType" \
	      [make_exception_pattern "TypeError" \
		   "Result from Disassembler must be gdb.DisassemblerResult, not Blah."]] \
	 [list "ResultOfVeryWrongType" \
	      [make_exception_pattern "TypeError" \
		   "Result from Disassembler must be gdb.DisassemblerResult, not Blah."]] \
	 [list "ErrorCreatingTextPart_NoArgs" \
	      [make_exception_pattern "TypeError" \
		   [missing_arg_pattern "style" 1]]] \
	 [list "ErrorCreatingAddressPart_NoArgs" \
	      [make_exception_pattern "TypeError" \
		   [missing_arg_pattern "address" 1]]] \
	 [list "ErrorCreatingTextPart_NoString" \
	      [make_exception_pattern "TypeError" \
		   [missing_arg_pattern "string" 2]]] \
	 [list "ErrorCreatingTextPart_NoStyle" \
	      [make_exception_pattern "TypeError" \
		   [missing_arg_pattern "style" 1]]] \
	 [list "All_Text_Part_Styles" "${addr_pattern}p1p2p3p4p5p6p7p8p9p10\r\n.*"] \
	 [list "ErrorCreatingTextPart_StringAndParts" \
	      [make_exception_pattern "ValueError" \
		  "Cannot use 'string' and 'parts' when creating gdb\\.disassembler\\.DisassemblerResult\\."]] \
	 [list "Build_Result_Using_All_Parts" \
	      "${addr_pattern}fake\treg, ${curr_pc_pattern}(?: <\[^>\]+>)?, 123\r\n.*"] \
	]

# Now execute each test plan.
foreach plan $test_plans {
    set global_disassembler_name [lindex $plan 0]
    set expected_pattern [lindex $plan 1]

    with_test_prefix "global_disassembler=${global_disassembler_name}" {
	# Remove all existing disassemblers.
	py_remove_all_disassemblers

	# If we have a disassembler to load, do it now.
	if { $global_disassembler_name != "" } {
	    gdb_test_no_output "python add_global_disassembler($global_disassembler_name)"
	}

	# Disassemble test, and check the disassembler output.
	gdb_test "disassemble test" $expected_pattern
    }
}

# Check some errors relating to DisassemblerResult creation.
with_test_prefix "DisassemblerResult errors" {
    gdb_test "python gdb.disassembler.DisassemblerResult(0, 'abc')" \
	[multi_line \
	     "ValueError.*: Length must be greater than 0." \
	     "Error occurred in Python.*"]
    gdb_test "python gdb.disassembler.DisassemblerResult(-1, 'abc')" \
	[multi_line \
	     "ValueError.*: Length must be greater than 0." \
	     "Error occurred in Python.*"]
    gdb_test "python gdb.disassembler.DisassemblerResult(1, '')" \
	[multi_line \
	     "ValueError.*: String must not be empty.*" \
	     "Error occurred in Python.*"]
}

# Check that the architecture specific disassemblers can override the
# global disassembler.
#
# First, register a global disassembler, and check it is in place.
with_test_prefix "GLOBAL tagging disassembler" {
    py_remove_all_disassemblers
    gdb_test_no_output "python gdb.disassembler.register_disassembler(TaggingDisassembler(\"GLOBAL\"), None)"
    gdb_test "disassemble test" "${base_pattern}\\s+## tag = GLOBAL\r\n.*"
}

# Now register an architecture specific disassembler, and check it
# overrides the global disassembler.
with_test_prefix "LOCAL tagging disassembler" {
    gdb_test_no_output "python gdb.disassembler.register_disassembler(TaggingDisassembler(\"LOCAL\"), \"${curr_arch}\")"
    gdb_test "disassemble test" "${base_pattern}\\s+## tag = LOCAL\r\n.*"
}

# Now remove the architecture specific disassembler, and check that
# the global disassembler kicks back in.
with_test_prefix "GLOBAL tagging disassembler again" {
    gdb_test_no_output "python gdb.disassembler.register_disassembler(None, \"${curr_arch}\")"
    gdb_test "disassemble test" "${base_pattern}\\s+## tag = GLOBAL\r\n.*"
}

# Check that a DisassembleInfo becomes invalid after the call into the
# disassembler.
with_test_prefix "DisassembleInfo becomes invalid" {
    py_remove_all_disassemblers
    gdb_test_no_output "python add_global_disassembler(GlobalCachingDisassembler)"
    gdb_test "disassemble test" "${base_pattern}\\s+## CACHED\r\n.*"
    gdb_test "python GlobalCachingDisassembler.check()" "PASS"
}

# Test the memory source aspect of the builtin disassembler.
with_test_prefix "memory source api" {
    py_remove_all_disassemblers
    gdb_test_no_output "python analyzing_disassembler = add_global_disassembler(AnalyzingDisassembler)"
    gdb_test "disassemble test" "${base_pattern}\r\n.*"
    gdb_test "python analyzing_disassembler.find_replacement_candidate()" \
	"Replace from $hex to $hex with NOP"
    gdb_test "disassemble test" "${base_pattern}\r\n.*" \
	"second disassembler pass"
    gdb_test "python analyzing_disassembler.check()" \
	"PASS"
}

# Test the 'maint info python-disassemblers command.
with_test_prefix "maint info python-disassemblers" {
    py_remove_all_disassemblers
    gdb_test "maint info python-disassemblers" "No Python disassemblers registered\\." \
	"list disassemblers, none registered"
    gdb_test_no_output "python disasm = add_global_disassembler(BuiltinDisassembler)"
    gdb_test "maint info python-disassemblers" \
	[multi_line \
	     "Architecture\\s+Disassember Name" \
	     "GLOBAL\\s+BuiltinDisassembler\\s+\\(Matches current architecture\\)"] \
	"list disassemblers, single global disassembler"
    gdb_test_no_output "python arch = gdb.selected_inferior().architecture().name()"
    gdb_test_no_output "python gdb.disassembler.register_disassembler(disasm, arch)"
    gdb_test "maint info python-disassemblers" \
	[multi_line \
	     "Architecture\\s+Disassember Name" \
	     "\[^\r\n\]+BuiltinDisassembler\\s+\\(Matches current architecture\\)" \
	     "GLOBAL\\s+BuiltinDisassembler"] \
	"list disassemblers, multiple disassemblers registered"

    # Check that disassembling main (with the BuiltinDisassembler in
    # place) doesn't cause GDB to crash.  The hope is that
    # disassembling main will result in a call to print_address, which
    # is where the problem was.
    gdb_test "disassemble main" ".*"
}

# Check the attempt to create a "new" DisassembleInfo object fails.
with_test_prefix "Bad DisassembleInfo creation" {
    gdb_test_no_output "python my_info = InvalidDisassembleInfo()"
    gdb_test "python print(my_info.is_valid())" "True"
    gdb_test "python gdb.disassembler.builtin_disassemble(my_info)" \
	[multi_line \
	     "RuntimeError.*: DisassembleInfo is no longer valid\\." \
	     "Error occurred in Python.*"]
}

# Some of the disassembler related types should not be sub-typed,
# check these now.
with_test_prefix "check inheritance" {
    foreach_with_prefix type {gdb.disassembler.DisassemblerResult \
				  gdb.disassembler.DisassemblerPart
				  gdb.disassembler.DisassemblerTextPart \
				  gdb.disassembler.DisassemblerAddressPart} {
	set type_ptn [string_to_regexp $type]
	gdb_test_multiline "Sub-class a breakpoint" \
	    "python" "" \
	    "class InvalidResultType($type):" "" \
	    "   def __init__(self):" "" \
	    "     pass" "" \
	    "end" \
	    [multi_line \
		 "TypeError.*: type '${type_ptn}' is not an acceptable base type" \
		 "Error occurred in Python.*"]
    }
}


# Test some error conditions when creating a DisassemblerResult object.
gdb_test "python result = gdb.disassembler.DisassemblerResult()" \
    [multi_line \
	 "TypeError.*: [missing_arg_pattern length 1]" \
	 "Error occurred in Python.*"] \
    "try to create a DisassemblerResult without a length argument"

foreach len {0 -1} {
    gdb_test "python result = gdb.disassembler.DisassemblerResult($len)" \
	[multi_line \
	     "ValueError.*: Length must be greater than 0\\." \
	     "Error occurred in Python.*"] \
	"try to create a DisassemblerResult with length $len"
}

# Check we can't directly create DisassemblerTextPart or
# DisassemblerAddressPart objects.
foreach type {DisassemblerTextPart DisassemblerAddressPart} {
    gdb_test "python result = gdb.disassembler.${type}()" \
	[multi_line \
	     "RuntimeError.*: Cannot create instances of DisassemblerPart\\." \
	     "Error occurred in Python.*"] \
	 "try to create an instance of ${type}"
}
