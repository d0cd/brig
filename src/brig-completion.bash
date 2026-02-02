#!/bin/bash
# Bash completion script for brig CLI.
#
# Installation:
#   source /path/to/brig-completion.bash
#
# Or add to ~/.bashrc:
#   source /path/to/brig-completion.bash

_brig_completions() {
    local cur prev words cword
    _get_comp_words_by_ref -n : cur prev words cword

    local commands="run stop kill rm start pause unpause list logs exec attach inspect export stats top diff files cat cp network diagnose verify policy"

    # First argument after 'brig' is the command (or --debug).
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands --debug" -- "$cur"))
        return 0
    fi

    # Handle --debug as first arg.
    if [[ ${words[1]} == "--debug" ]]; then
        if [[ $cword -eq 2 ]]; then
            COMPREPLY=($(compgen -W "$commands" -- "$cur"))
            return 0
        fi
        local cmd_idx=2
    else
        local cmd_idx=1
    fi

    local cmd=${words[$cmd_idx]}

    # Get list of cells for commands that need cell names.
    _brig_get_cells() {
        podman ps -a --format '{{.Names}}' --filter 'name=brig-' 2>/dev/null | sed 's/^brig-//'
    }

    case "$cmd" in
        run)
            case "$prev" in
                --name|-n)
                    return 0
                    ;;
                --file|-f)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return 0
                    ;;
                --memory|--cpus|--pids-limit)
                    return 0
                    ;;
                --env|-e|--secret|--policy-allow|--policy-deny)
                    return 0
                    ;;
            esac
            if [[ $cur == -* ]]; then
                COMPREPLY=($(compgen -W "--name -n --file -f --detach -d --rm --env -e --secret --memory --cpus --pids-limit --policy-allow --policy-deny" -- "$cur"))
            fi
            ;;
        stop|kill|start|pause|unpause|top|diff|attach|diagnose)
            if [[ $prev == "$cmd" ]]; then
                COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
            fi
            ;;
        rm)
            case "$prev" in
                rm)
                    if [[ $cur == -* ]]; then
                        COMPREPLY=($(compgen -W "-f --force --purge" -- "$cur"))
                    else
                        COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
                    fi
                    ;;
                -f|--force|--purge)
                    COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
                    ;;
            esac
            ;;
        logs)
            case "$prev" in
                logs)
                    if [[ $cur == -* ]]; then
                        COMPREPLY=($(compgen -W "-f --follow --tail" -- "$cur"))
                    else
                        COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
                    fi
                    ;;
                --tail)
                    return 0
                    ;;
                *)
                    COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
                    ;;
            esac
            ;;
        exec)
            if [[ $prev == "exec" ]] || [[ $prev == -* ]]; then
                if [[ $cur == -* ]]; then
                    COMPREPLY=($(compgen -W "-i --interactive -t --tty" -- "$cur"))
                else
                    COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
                fi
            fi
            ;;
        inspect|export)
            case "$prev" in
                "$cmd")
                    if [[ $cur == -* ]]; then
                        COMPREPLY=($(compgen -W "--format" -- "$cur"))
                    else
                        COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
                    fi
                    ;;
                --format)
                    if [[ $cmd == "inspect" ]]; then
                        COMPREPLY=($(compgen -W "table json" -- "$cur"))
                    else
                        COMPREPLY=($(compgen -W "yaml json" -- "$cur"))
                    fi
                    ;;
                *)
                    COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
                    ;;
            esac
            ;;
        stats)
            if [[ $cur == -* ]]; then
                COMPREPLY=($(compgen -W "--no-stream" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
            fi
            ;;
        list)
            if [[ $cur == -* ]]; then
                COMPREPLY=($(compgen -W "--format" -- "$cur"))
            elif [[ $prev == "--format" ]]; then
                COMPREPLY=($(compgen -W "table json" -- "$cur"))
            fi
            ;;
        files|cat)
            if [[ $prev == "$cmd" ]]; then
                COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
            fi
            ;;
        network)
            case "$prev" in
                network)
                    if [[ $cur == -* ]]; then
                        COMPREPLY=($(compgen -W "-f --follow --json --tail" -- "$cur"))
                    else
                        COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
                    fi
                    ;;
                *)
                    COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
                    ;;
            esac
            ;;
        policy)
            if [[ $prev == "policy" ]]; then
                COMPREPLY=($(compgen -W "show set" -- "$cur"))
            elif [[ $prev == "show" ]] || [[ $prev == "set" ]]; then
                COMPREPLY=($(compgen -W "$(_brig_get_cells)" -- "$cur"))
            elif [[ $cur == -* ]]; then
                COMPREPLY=($(compgen -W "--allow --deny --remove-allow --remove-deny" -- "$cur"))
            fi
            ;;
        verify)
            # No additional arguments.
            ;;
        cp)
            # File path completion.
            COMPREPLY=($(compgen -f -- "$cur"))
            ;;
    esac
}

complete -F _brig_completions brig
