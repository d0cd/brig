#compdef brig
# Zsh completion script for brig CLI.
#
# Installation:
#   Add to fpath and reload:
#     fpath=(/path/to/containing/dir $fpath)
#     autoload -Uz compinit && compinit
#
# Or copy to a fpath directory:
#   cp brig-completion.zsh ~/.zsh/completions/_brig

_brig_cells() {
    local cells
    cells=(${(f)"$(podman ps -a --format '{{.Names}}' --filter 'name=brig-' 2>/dev/null | sed 's/^brig-//')"})
    _describe 'cell' cells
}

_brig() {
    local -a commands
    commands=(
        'run:Run a new cell'
        'stop:Gracefully stop a cell'
        'kill:Immediately kill a cell'
        'rm:Remove a cell'
        'start:Start a stopped cell'
        'pause:Pause a running cell'
        'unpause:Unpause a paused cell'
        'list:List all cells'
        'logs:View cell logs'
        'exec:Execute command in cell'
        'attach:Attach to cell console'
        'inspect:Show cell details'
        'export:Export cell as YAML definition'
        'stats:Show cell resource usage'
        'top:Show processes in cell'
        'diff:Show filesystem changes from base image'
        'files:List workspace contents'
        'cat:View file in workspace'
        'cp:Copy files to/from workspace'
        'network:View cell network activity'
        'diagnose:Run diagnostic checks'
        'verify:Verify security invariants'
        'policy:Manage cell network policy'
    )

    local -a global_opts
    global_opts=(
        '--debug[Enable debug output]'
    )

    _arguments -C \
        $global_opts \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe 'command' commands
            ;;
        args)
            case $words[1] in
                run)
                    _arguments \
                        '--name[Cell name]:name:' \
                        '-n[Cell name]:name:' \
                        '--file[Cell definition file]:file:_files' \
                        '-f[Cell definition file]:file:_files' \
                        '--detach[Run in background]' \
                        '-d[Run in background]' \
                        '--rm[Remove when exits]' \
                        '*--env[Set environment variable]:env:' \
                        '*-e[Set environment variable]:env:' \
                        '*--secret[Mount secret file]:secret:' \
                        '--memory[Memory limit]:memory:' \
                        '--cpus[CPU limit]:cpus:' \
                        '--pids-limit[PID limit]:pids:' \
                        '*--policy-allow[Allow domain]:domain:' \
                        '*--policy-deny[Deny domain]:domain:' \
                        '*:image:_docker_images'
                    ;;
                stop|kill|start|pause|unpause|top|diff|attach|diagnose)
                    _arguments '1:cell:_brig_cells'
                    ;;
                rm)
                    _arguments \
                        '-f[Force remove]' \
                        '--force[Force remove]' \
                        '--purge[Remove workspace]' \
                        '1:cell:_brig_cells'
                    ;;
                logs)
                    _arguments \
                        '-f[Follow log output]' \
                        '--follow[Follow log output]' \
                        '--tail[Number of lines]:lines:' \
                        '1:cell:_brig_cells'
                    ;;
                exec)
                    _arguments \
                        '-i[Interactive mode]' \
                        '--interactive[Interactive mode]' \
                        '-t[Allocate pseudo-TTY]' \
                        '--tty[Allocate pseudo-TTY]' \
                        '1:cell:_brig_cells' \
                        '*:command:_command'
                    ;;
                inspect)
                    _arguments \
                        '--format[Output format]:format:(table json)' \
                        '1:cell:_brig_cells'
                    ;;
                export)
                    _arguments \
                        '--format[Output format]:format:(yaml json)' \
                        '1:cell:_brig_cells'
                    ;;
                stats)
                    _arguments \
                        '--no-stream[Disable live updates]' \
                        '1:cell:_brig_cells'
                    ;;
                list)
                    _arguments '--format[Output format]:format:(table json)'
                    ;;
                files)
                    _arguments \
                        '1:cell:_brig_cells' \
                        '2:path:'
                    ;;
                cat)
                    _arguments \
                        '--lines[Show only first N lines]:lines:' \
                        '-n[Show only first N lines]:lines:' \
                        '--max-size[Max file size in MB]:size:' \
                        '--force[Show binary files]' \
                        '1:cell:_brig_cells' \
                        '2:path:'
                    ;;
                cp)
                    _arguments \
                        '--sanitize[Block unsafe file types]' \
                        '1:source:_files' \
                        '2:destination:_files'
                    ;;
                network)
                    _arguments \
                        '-f[Follow log output]' \
                        '--follow[Follow log output]' \
                        '--json[Output raw JSONL]' \
                        '--tail[Number of lines]:lines:' \
                        '1:cell:_brig_cells'
                    ;;
                policy)
                    local -a policy_commands
                    policy_commands=(
                        'show:Show cell policy'
                        'set:Update cell policy'
                    )
                    _arguments \
                        '1: :->policy_cmd' \
                        '*:: :->policy_args'
                    case $state in
                        policy_cmd)
                            _describe 'policy command' policy_commands
                            ;;
                        policy_args)
                            case $words[1] in
                                show)
                                    _arguments '1:cell:_brig_cells'
                                    ;;
                                set)
                                    _arguments \
                                        '*--allow[Allow domain]:domain:' \
                                        '*--deny[Deny domain]:domain:' \
                                        '*--remove-allow[Remove allowed domain]:domain:' \
                                        '*--remove-deny[Remove denied domain]:domain:' \
                                        '1:cell:_brig_cells'
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
                verify)
                    # No additional arguments.
                    ;;
            esac
            ;;
    esac
}

_brig "$@"
