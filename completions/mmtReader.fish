# mmtReader fish completion
#
# Install:
#   mkdir -p ~/.config/fish/completions
#   cp completions/mmtReader.fish ~/.config/fish/completions/mmtReader.fish
#
# Or system-wide:
#   sudo cp completions/mmtReader.fish /usr/share/fish/completions/mmtReader.fish

complete -c mmtReader -n '__fish_use_subcommand' -x -s q -l quiet -d 'Suppress progress output'
complete -c mmtReader -n '__fish_use_subcommand' -x -s v -l verbose -d 'Show verbose debug output'
complete -c mmtReader -n '__fish_use_subcommand' -x -s h -l help -d 'Show help message'
complete -c mmtReader -n '__fish_use_subcommand' -x -s V -l version -d 'Print version information'
complete -c mmtReader -n '__fish_use_subcommand' -x -s C -l no-color -d 'Disable ANSI color output'

complete -c mmtReader -n '__fish_use_subcommand' -x -s x -l ip-classify -d 'IP address classification (0 or 1)' -r -f -a '0 1'
complete -c mmtReader -n '__fish_use_subcommand' -x -s y -l hostname-classify -d 'Hostname classification (0 or 1)' -r -f -a '0 1'
complete -c mmtReader -n '__fish_use_subcommand' -x -s z -l port-classify -d 'Port number classification (0 or 1)' -r -f -a '0 1'

complete -c mmtReader -n '__fish_use_subcommand' -x -s j -l json -d 'Output statistics in JSON format'
complete -c mmtReader -n '__fish_use_subcommand' -x -s T -l text -d 'Set text output format (default)'

complete -c mmtReader -n '__fish_use_subcommand' -x -s a -l proto-path -d 'Show per-protocol-path statistics'
complete -c mmtReader -n '__fish_use_subcommand' -x -s s -l sessions -d 'Show per-protocol session counts'

# Subcommand: analyze
complete -c mmtReader -n '__fish_seen_subcommand_from analyze' -x -s t -l trace -d 'Trace file to analyze (required)' -f -a '(__fish_complete_suffix pcap)'
complete -c mmtReader -n '__fish_seen_subcommand_from analyze' -x -s b -l buffer -d 'PCAP buffer size in MB (default: 50)' -r -f -a '1 10 25 50 100 250 500 1000 5000'

# Subcommand: capture
complete -c mmtReader -n '__fish_seen_subcommand_from capture' -x -s i -l interface -d 'Network interface to capture from (required)' -r -f -a '(__fish_list_network_interfaces)'
complete -c mmtReader -n '__fish_seen_subcommand_from capture' -x -s b -l buffer -d 'PCAP buffer size in MB (default: 50)' -r -f -a '1 10 25 50 100 250 500 1000 5000'

# Subcommands at top level
complete -c mmtReader -n '__fish_use_subcommand' -f -a 'analyze' -d 'Analyze a PCAP trace file'
complete -c mmtReader -n '__fish_use_subcommand' -f -a 'capture' -d 'Capture and analyze live network traffic'
