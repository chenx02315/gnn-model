"""Fixed help-only Tcl candidate; no process, I/O or execution authority."""
COMMANDS = ('help', 'read_patterns', 'simulate_patterns', 'report_patterns')


def render_help_tcl():
    lines = ['set_context patterns -scan -design_identifier e136help']
    for command in COMMANDS:
        lines.extend(['puts "E136_HELP_BEGIN='+command+'"', 'help '+command,
                      'puts "E136_HELP_END='+command+'"'])
    lines.extend(['puts "E136_HELP_FINISHED"', 'exit'])
    return ('\n'.join(lines)+'\n').encode('ascii')
