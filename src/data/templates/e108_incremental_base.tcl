# Incremental common-fault ATPG. STATUS_FILE must already use the target
# mode's native paths and contain detected classes only (DS/DI*).
foreach required {CIRCUIT_ROOT CIRCUIT TOP_MODULE CELL_LIBRARY MODE RUN_ID COMMON_FAULT_DIR TSDB_INPUT_DIR STATUS_FILE STATUS_TRANSLATION_MANIFEST} {
  if {![info exists ::env($required)]} { puts stderr "ERROR: missing $required"; exit 2 }
}
set root [file normalize $::env(CIRCUIT_ROOT)]
set circuit $::env(CIRCUIT)
set top $::env(TOP_MODULE)
set lib [file normalize $::env(CELL_LIBRARY)]
set mode $::env(MODE)
set run_id $::env(RUN_ID)
set status [file normalize $::env(STATUS_FILE)]
set translation_manifest [file normalize $::env(STATUS_TRANSLATION_MANIFEST)]
set common_source [file join $root 03_fault_universe $::env(COMMON_FAULT_DIR) ${mode}_common_initial_faults.basic]
set phase 05_two_mode
if {[info exists ::env(PHASE)]} { set phase $::env(PHASE) }
if {![file exists $status]} { puts stderr "ERROR: missing translated status $status"; exit 2 }
if {![file exists $translation_manifest]} { puts stderr "ERROR: missing translation manifest $translation_manifest"; exit 2 }
if {![file exists $common_source]} { puts stderr "ERROR: missing target common faults $common_source"; exit 2 }
set out [file join $root $phase ${mode}_${run_id}]
if {[file exists $out]} { puts stderr "ERROR: refusing to overwrite $out"; exit 3 }
file mkdir $out
set_context patterns -scan -design_identifier ${circuit}_${mode}_mapped_incremental_${run_id}
set tsdb_input [file normalize $::env(TSDB_INPUT_DIR)]
if {![file isdirectory $tsdb_input]} { puts stderr "ERROR: missing isolated TSDB $tsdb_input"; exit 2 }
set_tsdb_output_directory $tsdb_input
read_cell_library $lib
read_design $top -design_identifier ${circuit}_${mode}_mapped_insert -verbose
set_current_design $top
if {$mode eq "F"} {
  set_current_mode F_mapped_incremental_${run_id}
  import_scan_mode F_fullscan_4ch
} else {
  set_current_mode ${mode}_mapped_incremental_${run_id}
  import_scan_mode edt_mode
  set_static_dft_signal_values async_set_reset_static_disable 1
}
set_clock_off_simulation ON
set_split_capture_cycle ON
set_system_mode analysis
add_processors localhost:1
set_random_atpg OFF
if {$mode eq "F"} { set_atpg_fill X }
set_fault_type Stuck
# The translated file contains only detection information.  Non-detected
# classes remain native to this target mode and are re-analysed here.  Load
# the complete target-native common universe first; merging a subset alone
# would silently shrink FU to only the already-detected subset.
read_faults $common_source -show_warnings
read_faults $status -merge -show_warnings
reset_au_faults -reclassify
report_statistics -detailed_analysis > [file join $out pre_atpg_statistics.rpt]
if {[info exists ::env(PATTERN_LIMIT)] && $::env(PATTERN_LIMIT) ne "" && [info exists ::env(TEST_COVERAGE_LIMIT)] && $::env(TEST_COVERAGE_LIMIT) ne ""} {
  puts stderr "ERROR: set only one of PATTERN_LIMIT or TEST_COVERAGE_LIMIT"
  exit 2
}
if {[info exists ::env(PATTERN_LIMIT)] && $::env(PATTERN_LIMIT) ne ""} {
  set_atpg_limits -Pattern_count $::env(PATTERN_LIMIT)
  puts "ATPG_PATTERN_LIMIT=$::env(PATTERN_LIMIT)"
} elseif {[info exists ::env(TEST_COVERAGE_LIMIT)] && $::env(TEST_COVERAGE_LIMIT) ne ""} {
  set_atpg_limits -Test_coverage $::env(TEST_COVERAGE_LIMIT)
  puts "ATPG_TEST_COVERAGE_LIMIT=$::env(TEST_COVERAGE_LIMIT)"
} else {
  set_atpg_limits Off
  puts "ATPG_PATTERN_LIMIT=FULL"
}
create_patterns -compaction_effort High -coverage_effort High
report_statistics -detailed_analysis > [file join $out statistics.rpt]
report_patterns > [file join $out patterns.rpt]
report_scan_volume > [file join $out scan_volume.rpt]
report_faults > [file join $out faults.rpt]
report_procedures > [file join $out procedures.rpt]
write_faults [file join $out faults.mtfi] -replace -format Mtfi
write_patterns [file join $out tester.stil] -stil -replace
puts "MAPPED_INCREMENTAL_ATPG_STATUS=PASS"
puts "MAPPED_INCREMENTAL_MODE=$mode"
puts "MAPPED_INCREMENTAL_RUN_ID=$run_id"
puts "MAPPED_INCREMENTAL_TRANSLATED_STATUS_FILE=$status"
puts "MAPPED_INCREMENTAL_TRANSLATION_MANIFEST=$translation_manifest"
exit
