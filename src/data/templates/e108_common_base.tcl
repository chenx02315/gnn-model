# One unique common-fault ATPG run for mapped-netlist flow.
# Required: CIRCUIT_ROOT, CIRCUIT, TOP_MODULE, CELL_LIBRARY, MODE, RUN_ID.
# Optional: PATTERN_LIMIT (positive integer; omitted means full ATPG).
foreach required {CIRCUIT_ROOT CIRCUIT TOP_MODULE CELL_LIBRARY MODE RUN_ID TSDB_INPUT_DIR} {
  if {![info exists ::env($required)]} { puts stderr "ERROR: missing $required"; exit 2 }
}
set root [file normalize $::env(CIRCUIT_ROOT)]
set circuit $::env(CIRCUIT)
set top $::env(TOP_MODULE)
set lib [file normalize $::env(CELL_LIBRARY)]
set mode $::env(MODE)
set run_id $::env(RUN_ID)
set phase single_mode
if {[info exists ::env(PHASE)]} { set phase $::env(PHASE) }
set out [file join $root 04_single_mode ${mode}_${run_id}]
if {$phase ne "single_mode"} { set out [file join $root $phase ${mode}_${run_id}] }
if {[file exists $out]} { puts stderr "ERROR: refusing to overwrite $out"; exit 3 }
file mkdir $out
set common_dir common_b14_mapped_v0_4
if {[info exists ::env(COMMON_FAULT_DIR)] && $::env(COMMON_FAULT_DIR) ne ""} {
  set common_dir $::env(COMMON_FAULT_DIR)
}
set source [file join $root 03_fault_universe $common_dir ${mode}_common_initial_faults.basic]
if {![file exists $source]} { puts stderr "ERROR: missing $source"; exit 2 }
set_context patterns -scan -design_identifier ${circuit}_${mode}_mapped_atpg_${run_id}
set tsdb_input [file normalize $::env(TSDB_INPUT_DIR)]
if {![file isdirectory $tsdb_input]} { puts stderr "ERROR: missing isolated TSDB $tsdb_input"; exit 2 }
set_tsdb_output_directory $tsdb_input
read_cell_library $lib
read_design $top -design_identifier ${circuit}_${mode}_mapped_insert -verbose
set_current_design $top
if {$mode eq "F"} {
  set_current_mode F_mapped_atpg_${run_id}
  import_scan_mode F_fullscan_4ch
} else {
  set_current_mode ${mode}_mapped_atpg_${run_id}
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
read_faults $source -show_warnings
if {[info exists ::env(PATTERN_LIMIT)] && $::env(PATTERN_LIMIT) ne ""} {
  set_atpg_limits -Pattern_count $::env(PATTERN_LIMIT)
  puts "ATPG_PATTERN_LIMIT=$::env(PATTERN_LIMIT)"
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
# Screening/repeat evidence is fully preserved in reports, STIL, and MTFI.
# Avoid per-run TSDB writes on the nearly full NFS-backed A-side home volume.
puts "MAPPED_COMMON_ATPG_STATUS=PASS"
puts "MAPPED_COMMON_ATPG_MODE=$mode"
puts "MAPPED_COMMON_ATPG_RUN_ID=$run_id"
exit
