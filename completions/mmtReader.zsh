# mmtReader zsh completion
#
# Install:
#   mkdir -p ~/.zsh/completions
#   cp completions/mmtReader.zsh ~/.zsh/completions/_mmtReader
#   Add ~/.zsh/completions to $fpath in ~/.zshrc
#
# Or system-wide:
#   sudo cp completions/mmtReader.zsh /usr/share/zsh/site-functions/_mmtReader

#compdef mmtReader

_mmtReader() {
    local -a subcommands
    subcommands=(
        'analyze:Analyze a PCAP trace file'
        'capture:Capture and analyze live network traffic'
    )

    local -a global_opts
    global_opts=(
        '-q:Suppress progress output'
        '--quiet:Suppress progress output'
        '-v:Show verbose debug output'
        '--verbose:Show verbose debug output'
        '-h:Show help message'
        '--help:Show help message'
        '-V:Print version information'
        '--version:Print version information'
        '-C:Disable ANSI color output'
        '--no-color:Disable ANSI color output'
    )

    local -a classify_opts
    classify_opts=(
        '-x:IP address classification (0 or 1)'
        '--ip-classify:IP address classification (0 or 1)'
        '-y:Hostname classification (0 or 1)'
        '--hostname-classify:Hostname classification (0 or 1)'
        '-z:Port number classification (0 or 1)'
        '--port-classify:Port number classification (0 or 1)'
    )

    local -a format_opts
    format_opts=(
        '-j:Output statistics in JSON format'
        '--json:Output statistics in JSON format'
        '-T:Set text output format (default)'
        '--text:Set text output format (default)'
    )

    local -a feature_opts
    feature_opts=(
        '-a:Show per-protocol-path statistics'
        '--proto-path:Show per-protocol-path statistics'
        '-s:Show per-protocol session counts'
        '--sessions:Show per-protocol session counts'
    )

    local -a arg_opts
    arg_opts=(
        '-t:[TRACE_FILE:_files "*.pcap"]'
        '--trace=[TRACE_FILE:_files "*.pcap"]'
        '-i:[INTERFACE:(ls /sys/class/net/)]'
        '--interface=[INTERFACE:(ls /sys/class/net/)]'
        '-b:[BUFFER_SIZE:((1,10000))]'
        '--buffer=[BUFFER_SIZE:((1,10000))]'
    )

    local -a all_opts
    all_opts=("${global_opts[@]}" "${classify_opts[@]}" "${format_opts[@]}" "${feature_opts[@]}" "${arg_opts[@]}")

    local curcontext="$curcontext"
    local state state_descr line

    _arguments -C \
        "${all_opts[@]}" \
        '::subcommand:->subcommand' \
        && return

    case $state in
        subcommand)
            _describe 'subcommand' subcommands
            ;;
    esac
}

# Load and run the completion
_mmtReader
