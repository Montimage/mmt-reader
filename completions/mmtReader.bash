# mmtReader bash completion
#
# Install:
#   sudo cp completions/mmtReader.bash /usr/share/bash-completion/completions/mmtReader
#
# Or source manually:
#   source completions/mmtReader.bash

_mmtReader_completions() {
    local cur prev words cword
    _init_completion || return

    # Subcommands
    local subcommands="analyze capture"

    # Global options
    local global_opts="-q --quiet -v --verbose -h --help -V --version -C --no-color"

    # Classification flags
    local classify_opts="-x --ip-classify -y --hostname-classify -z --port-classify"

    # Output format flags
    local format_opts="-j --json -T --text"

    # Feature flags
    local feature_opts="-a --proto-path -s --sessions"

    # Options requiring arguments
    local arg_opts="-t --trace -i --interface -b --buffer"

    # Flags offered only after the 'capture' subcommand
    local capture_opts="-F --flows"

    if [[ ${cword} -eq 1 ]]; then
        # Top-level: suggest subcommands
        COMPREPLY=( $(compgen -W "${subcommands}" -- "${cur}") )
        return
    fi

    # Determine subcommand
    local subcmd="${words[1]}"

    # Options available with any subcommand, plus the capture-only ones
    local all_opts="${global_opts} ${classify_opts} ${format_opts} ${feature_opts} ${arg_opts}"
    if [[ "${subcmd}" == "capture" ]]; then
        all_opts="${all_opts} ${capture_opts}"
    fi

    if [[ ${cword} -eq 2 ]]; then
        # Second word: subcommand or option
        if [[ "${prev}" == "--" ]]; then
            # -- followed by long option
            COMPREPLY=( $(compgen -W "${all_opts}" -- "${cur}") )
            return
        fi
        COMPREPLY=( $(compgen -W "${subcommands} ${all_opts}" -- "${cur}") )
        return
    fi

    case "${prev}" in
        -t|--trace)
            # File path completion for trace file
            COMPREPLY=( $(compgen -f -- "${cur}" | grep '\.pcap$') )
            if [[ ${#COMPREPLY[@]} -eq 0 ]]; then
                COMPREPLY=( $(compgen -f -- "${cur}") )
            fi
            return
            ;;
        -i|--interface)
            # Network interface completion
            local interfaces
            interfaces=$(ls /sys/class/net/ 2>/dev/null | tr '\n' ' ')
            if [[ -n "${interfaces}" ]]; then
                COMPREPLY=( $(compgen -W "${interfaces}" -- "${cur}") )
            fi
            return
            ;;
        -b|--buffer)
            # Integer completion for buffer size
            COMPREPLY=( $(compgen -W "1 10 25 50 100 250 500 1000 5000" -- "${cur}") )
            return
            ;;
        -F|--flows)
            # Integer completion for capture duration in seconds
            COMPREPLY=( $(compgen -W "5 10 30 60 120 300" -- "${cur}") )
            return
            ;;
        -x|--ip-classify|-y|--hostname-classify|-z|--port-classify)
            # Boolean: 0 or 1
            COMPREPLY=( $(compgen -W "0 1" -- "${cur}") )
            return
            ;;
        -h|--help|-V|--version)
            # No completion for these
            return
            ;;
    esac

    case "${cur}" in
        -*)
            COMPREPLY=( $(compgen -W "${all_opts}" -- "${cur}") )
            ;;
        *)
            # If cur matches a subcommand, complete options for that subcommand
            if [[ "${cur}" == "analy"* || "${cur}" == "capt"* ]]; then
                COMPREPLY=( $(compgen -W "${subcommands} ${all_opts}" -- "${cur}") )
            else
                COMPREPLY=( $(compgen -W "${all_opts}" -- "${cur}") )
            fi
            ;;
    esac
}

complete -F _mmtReader_completions mmtReader
