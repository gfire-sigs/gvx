// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"io"
	"strings"
)

func init() {
	register(command{
		name:    "completion",
		summary: "Print shell completion scripts for bash, zsh, fish, or powershell.",
		usage:   []string{"rungv completion <bash|zsh|fish|powershell>"},
		run:     completionSubcommand,
	})
}

func completionSubcommand(_ context.Context, args []string, streams cliIO) int {
	fs := newImageFlagSet("completion", streams.stderr)
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 1 {
		return imageUsageError(streams.stderr, "completion", "want one shell argument (bash, zsh, fish, or powershell)")
	}
	shell := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	var script string
	switch shell {
	case "bash":
		script = bashCompletionScript
	case "zsh":
		script = zshCompletionScript
	case "fish":
		script = fishCompletionScript
	case "powershell", "pwsh":
		script = powershellCompletionScript
	default:
		return imageUsageError(streams.stderr, "completion", "unsupported shell %q (want bash, zsh, fish, or powershell)", fs.Arg(0))
	}
	if _, err := io.WriteString(streams.stdout, script); err != nil {
		return imageFail(streams.stderr, "completion", err)
	}
	return 0
}

const bashCompletionScript = `# bash completion for rungv
_rungv_completions() {
    local cur prev words cword
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local top_cmds="run exec pause unpause cp export update port port-forward pf net-policy mount status sandbox stats top kill stop dmesg events ping debug pull images rmi inspect tag save load login logout image volume system info tune checkpoint snapshot restore resume version license completion help"
    local image_cmds="ls list pull rm remove rmi inspect tag save load prune"
    local volume_cmds="create ls list inspect compact rm remove prune"
    local system_cmds="info df prune"
    local port_cmds="ls list add rm remove"
    local mount_cmds="ls list add remount rm remove serve"
    local sandbox_cmds="inspect"
    local shells="bash zsh fish powershell"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${top_cmds}" -- "${cur}") )
        return 0
    fi

    case "${COMP_WORDS[1]}" in
        image)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${image_cmds}" -- "${cur}") )
                return 0
            fi
            ;;
        volume)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${volume_cmds}" -- "${cur}") )
                return 0
            fi
            ;;
        system)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${system_cmds}" -- "${cur}") )
                return 0
            fi
            ;;
        port)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${port_cmds}" -- "${cur}") )
                return 0
            fi
            ;;
        net-policy)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "get replace" -- "${cur}") )
            elif [[ "${prev}" == --file || "${prev}" == -file ]]; then
                COMPREPLY=( $(compgen -f -- "${cur}") )
            elif [[ "${cur}" == -* ]]; then
                local flags="-S --control-socket -n --name --token --token-file --timeout --help"
                [[ "${COMP_WORDS[2]}" == replace ]] && flags+=" --file"
                COMPREPLY=( $(compgen -W "${flags}" -- "${cur}") )
            fi
            ;;
        mount)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${mount_cmds}" -- "${cur}") )
                return 0
            fi
            ;;
        sandbox)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${sandbox_cmds}" -- "${cur}") )
                return 0
            fi
            ;;
        completion)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${shells}" -- "${cur}") )
                return 0
            fi
            ;;
        run)
            case "${prev}" in
                --nat-policy-file|-nat-policy-file)
                    COMPREPLY=( $(compgen -f -- "${cur}") )
                    return 0
                    ;;
                --backend|-backend)
                    COMPREPLY=( $(compgen -W "auto whpx hvf systrap" -- "${cur}") )
                    return 0
                    ;;
                --platform|-platform)
                    COMPREPLY=( $(compgen -W "linux/amd64 linux/arm64" -- "${cur}") )
                    return 0
                    ;;
                --net|-net)
                    COMPREPLY=( $(compgen -W "nat wg none" -- "${cur}") )
                    return 0
                    ;;
                --control-policy)
                    COMPREPLY=( $(compgen -W "default readonly checkpoint-only" -- "${cur}") )
                    return 0
                    ;;
            esac
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=( $(compgen -W "-i -t -w --workdir -workspace -v --volume --mount --rootfs-volume -p -P --auto-publish --dynamic-ports -e --env-file -u --user -m --memory --cpus --pids-limit --net --net-tx-bps --net-rx-bps --nat-policy-file --backend --platform --pull --entrypoint --rm -cache-dir -S --control-socket --control --control-policy --control-disable --control-token-file --allow-volume-attach --help" -- "${cur}") )
                return 0
            fi
            ;;
        exec)
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=( $(compgen -W "-S --control-socket -n --name --token --token-file --timeout -i -t -it -d -e --env-file -w --workdir -u --user --privileged --detach-keys --pid-file --help" -- "${cur}") )
                return 0
            fi
            ;;
        update)
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=( $(compgen -W "-S --control-socket -n --name --token --token-file --timeout -m --memory --force-memory --cpus --cpu-quota --cpu-period --pids-limit --isolate-lan --net-tx-bps --net-rx-bps --tune -f --format --help" -- "${cur}") )
                return 0
            fi
            ;;
        restore|resume)
            if [[ "${prev}" == --nat-policy-file || "${prev}" == -nat-policy-file ]]; then
                COMPREPLY=( $(compgen -f -- "${cur}") )
            elif [[ "${cur}" == -* ]]; then
                COMPREPLY=( $(compgen -W "--net-tx-bps --net-rx-bps --nat-policy-file" -- "${cur}") )
            fi
            ;;
    esac
}
complete -F _rungv_completions rungv
`

const zshCompletionScript = `#compdef rungv

_rungv() {
    local -a top_cmds image_cmds volume_cmds system_cmds port_cmds mount_cmds sandbox_cmds shells
    top_cmds=(
        'run:Create and run a sandboxed Linux guest'
        'exec:Execute a command inside a running sandbox'
        'pause:Pause all guest tasks in a running sandbox'
        'unpause:Resume guest tasks in a paused sandbox'
        'cp:Copy files between the host and a running sandbox'
        'export:Export a sandbox filesystem or overlay upper layer as tar'
        'update:Update live resource limits and mutable tunables'
        'port:Manage published ports of a running sandbox'
        'port-forward:Forward local ports into a sandbox over the control socket'
        'net-policy:Read or replace the host NAT firewall policy'
        'mount:Manage runtime mounts of a running sandbox'
        'status:Inspect a running sandbox over its control socket'
        'sandbox:Inspect a running sandbox'
        'stats:Display live sandbox resource statistics'
        'top:Display running processes inside a sandbox'
        'kill:Send a POSIX signal to a sandbox or guest PID'
        'stop:Gracefully stop a running sandbox'
        'dmesg:Read or follow the guest kernel log ring'
        'events:Stream real-time sandbox lifecycle events'
        'ping:Verify control socket liveness'
        'debug:Adjust runtime diagnostics'
        'pull:Download an OCI image into the EROFS layer cache'
        'images:List cached images'
        'rmi:Remove cached images'
        'inspect:Print detailed image metadata'
        'tag:Tag a cached image'
        'save:Write cached images to a tar archive'
        'load:Load images from a tar archive'
        'login:Store registry credentials'
        'logout:Remove registry credentials'
        'image:Manage cached OCI images'
        'volume:Manage named local volumes'
        'system:Inspect host backends and disk usage'
        'info:Display host environment and backend information'
        'tune:List host-side tunables'
        'checkpoint:Checkpoint a running sandbox'
        'restore:Restore a sandbox from a checkpoint directory'
        'version:Print rungv version metadata'
        'license:Print third-party license notices'
        'completion:Print shell completion scripts'
        'help:Print command usage'
    )
    image_cmds=(ls list pull rm remove rmi inspect tag save load prune)
    volume_cmds=(create ls list inspect compact rm remove prune)
    system_cmds=(info df prune)
    port_cmds=(ls list add rm remove)
    mount_cmds=(ls list add remount rm remove serve)
    sandbox_cmds=(inspect)
    shells=(bash zsh fish powershell)

    if (( CURRENT == 2 )); then
        _describe -t commands 'rungv command' top_cmds
        return
    fi

    case "${words[2]}" in
        image)
            (( CURRENT == 3 )) && compadd -a image_cmds
            ;;
        volume)
            (( CURRENT == 3 )) && compadd -a volume_cmds
            ;;
        system)
            (( CURRENT == 3 )) && compadd -a system_cmds
            ;;
        port)
            (( CURRENT == 3 )) && compadd -a port_cmds
            ;;
        net-policy)
            if (( CURRENT == 3 )); then
                compadd get replace
            else
                local -a flags
                flags=(
                    '-S[Control socket]:socket:'
                    '--control-socket[Control socket]:socket:'
                    '(-n --name)'{-n,--name}'[Sandbox name]:name:'
                    '--token[Control token]:token:'
                    '--token-file[Control token file]:file:_files'
                    '--timeout[RPC timeout]:duration:'
                    '--help[Print command usage]'
                )
                [[ "${words[3]}" == replace ]] && flags+=('--file[Replacement NAT firewall policy]:file:_files')
                _arguments "${flags[@]}"
            fi
            ;;
        mount)
            (( CURRENT == 3 )) && compadd -a mount_cmds
            ;;
        sandbox)
            (( CURRENT == 3 )) && compadd -a sandbox_cmds
            ;;
        completion)
            (( CURRENT == 3 )) && compadd -a shells
            ;;
        run)
            _arguments \
                '-i[Keep stdin open]' \
                '-t[Allocate a pseudo-TTY]' \
                '-w[Working directory inside guest]:dir:' \
                '--workdir[Working directory inside guest]:dir:' \
                '-workspace[Host directory mounted at /workspace]:dir:_files -/' \
                '*-v[Bind or named volume mount]:spec:' \
                '*--mount[Structured mount specification]:spec:' \
                '--rootfs-volume[Persistent ext4lite volume name or image path for container rootfs]:volume:' \
                '*-p[Publish guest port to host]:port:' \
                '-P[Publish all exposed image ports]' \
                '--auto-publish[Automatically publish guest listeners on host 127.0.0.1]' \
                '--dynamic-ports[Allow runtime loopback port publishing via rungv port add]' \
                '*-e[Set guest environment variable]:env:' \
                '*--env-file[Read environment variables from file]:file:_files' \
                '-u[Guest user or UID:GID]:user:' \
                '-m[Guest memory limit]:bytes:' \
                '--cpus[Guest CPU quota]:cpus:' \
                '--pids-limit[Guest maximum process count]:limit:' \
                '-S[Control socket path or loopback TCP address]:socket:' \
                '--control-socket[Control socket path or loopback TCP address]:socket:' \
                '--control[Bind named control socket automatically]' \
                '--control-policy[Control capability policy]:policy:(default readonly checkpoint-only)' \
                '--control-disable[Disable control capabilities]:caps:' \
                '--control-token-file[Control token file path]:file:_files' \
                '--allow-volume-attach[Allow POSIX SCM_RIGHTS volume attachment under lockdown]' \
                '--net[Network mode]:mode:(nat wg none)' \
                '--net-tx-bps[Limit NAT traffic from guest to host]:bps:' \
                '--net-rx-bps[Limit NAT traffic from host to guest]:bps:' \
                '--nat-policy-file[Read host NAT firewall policy]:file:_files' \
                '--backend[Execution backend]:backend:(auto whpx hvf systrap)' \
                '--platform[Target image platform]:platform:(linux/amd64 linux/arm64)' \
                '--pull[Image pull policy]:policy:(missing always never)'
            ;;
        restore|resume)
            _arguments \
                '--net-tx-bps[Limit NAT traffic from guest to host]:bps:' \
                '--net-rx-bps[Limit NAT traffic from host to guest]:bps:' \
                '--nat-policy-file[Read host NAT firewall policy]:file:_files'
            ;;
        update)
            _arguments \
                '--net-tx-bps[Limit NAT traffic from guest to host]:bps:' \
                '--net-rx-bps[Limit NAT traffic from host to guest]:bps:'
            ;;
    esac
}

compdef _rungv rungv
`

const fishCompletionScript = `# fish completion for rungv
complete -c rungv -f

set -l __rungv_top_cmds run exec pause unpause cp export update port port-forward pf net-policy mount status sandbox stats top kill stop dmesg events ping debug pull images rmi inspect tag save load login logout image volume system info tune checkpoint snapshot restore resume version license completion help

complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a run -d "Run a command in a new sandbox"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a exec -d "Execute a command inside a running sandbox"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a pause -d "Pause all guest tasks"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a unpause -d "Resume paused guest tasks"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a cp -d "Copy files between host and sandbox"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a export -d "Export sandbox filesystem as tar"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a update -d "Update live resource limits"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a port -d "Manage published sandbox ports"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a port-forward -d "Tunnel local ports over control socket"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a net-policy -d "Read or replace the host NAT firewall policy"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a mount -d "Manage runtime sandbox mounts"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a status -d "Inspect a running sandbox"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a sandbox -d "Inspect a running sandbox"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a stats -d "Display live sandbox resource stats"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a top -d "List guest processes"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a kill -d "Signal a sandbox or guest PID"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a stop -d "Gracefully stop a running sandbox"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a dmesg -d "Read guest kernel logs"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a events -d "Stream sandbox lifecycle events"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a ping -d "Verify control socket liveness"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a debug -d "Adjust runtime diagnostics"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a pull -d "Download an OCI image"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a images -d "List cached images"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a rmi -d "Remove cached images"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a inspect -d "Inspect cached images"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a tag -d "Tag a cached image"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a save -d "Save images to a tar archive"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a load -d "Load images from a tar archive"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a login -d "Log in to a registry"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a logout -d "Log out from a registry"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a image -d "Manage cached OCI images"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a volume -d "Manage named local volumes"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a system -d "Inspect host backends and disk usage"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a info -d "Display host environment information"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a tune -d "List host-side tunables"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a checkpoint -d "Checkpoint a running sandbox"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a restore -d "Restore a checkpointed sandbox"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a version -d "Print version information"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a license -d "Print license notices"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a completion -d "Generate shell completion script"

complete -c rungv -n "__fish_seen_subcommand_from image; and not __fish_seen_subcommand_from ls list pull rm remove rmi inspect tag save load prune" -a "ls pull rm inspect tag save load prune"
complete -c rungv -n "__fish_seen_subcommand_from volume; and not __fish_seen_subcommand_from create ls list inspect compact rm remove prune" -a "create ls inspect compact rm prune"
complete -c rungv -n "__fish_seen_subcommand_from system; and not __fish_seen_subcommand_from info df prune" -a "info df prune"
complete -c rungv -n "__fish_seen_subcommand_from port; and not __fish_seen_subcommand_from ls list add rm remove" -a "ls add rm"
complete -c rungv -n "__fish_seen_subcommand_from net-policy; and not __fish_seen_subcommand_from get replace" -a "get replace"
complete -c rungv -n "__fish_seen_subcommand_from net-policy; and __fish_seen_subcommand_from get replace" -s S -l control-socket -r -d "Control socket"
complete -c rungv -n "__fish_seen_subcommand_from net-policy; and __fish_seen_subcommand_from get replace" -s n -l name -r -d "Sandbox name"
complete -c rungv -n "__fish_seen_subcommand_from net-policy; and __fish_seen_subcommand_from replace" -l file -rF -d "Replacement NAT firewall policy"
complete -c rungv -n "__fish_seen_subcommand_from mount; and not __fish_seen_subcommand_from ls list add remount rm remove serve" -a "ls add remount rm serve"
complete -c rungv -n "__fish_seen_subcommand_from sandbox; and not __fish_seen_subcommand_from inspect" -a "inspect"
complete -c rungv -n "__fish_seen_subcommand_from completion" -a "bash zsh fish powershell"
complete -c rungv -n "__fish_seen_subcommand_from run restore resume update" -l net-tx-bps -r -d "Limit NAT traffic from guest to host"
complete -c rungv -n "__fish_seen_subcommand_from run restore resume update" -l net-rx-bps -r -d "Limit NAT traffic from host to guest"
complete -c rungv -n "__fish_seen_subcommand_from run restore resume" -l nat-policy-file -rF -d "Read host NAT firewall policy"
`

const powershellCompletionScript = `# PowerShell completion for rungv
Register-ArgumentCompleter -Native -CommandName rungv -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $tokens = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }
    $topCmds = @('run','exec','pause','unpause','cp','export','update','port','port-forward','pf','net-policy','mount','status','sandbox','stats','top','kill','stop','dmesg','events','ping','debug','pull','images','rmi','inspect','tag','save','load','login','logout','image','volume','system','info','tune','checkpoint','snapshot','restore','resume','version','license','completion','help')

    if ($tokens.Count -le 1 -or ($tokens.Count -eq 2 -and $wordToComplete -ne '')) {
        $topCmds | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        return
    }

    $sub = $tokens[1]
    if ($sub -in @('run','restore','resume','update') -and $wordToComplete -like '-*') {
        $flags = @('--net-tx-bps','--net-rx-bps')
        if ($sub -ne 'update') { $flags += '--nat-policy-file' }
        $flags | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterName', $_)
        }
        return
    }
    if ($sub -eq 'net-policy' -and $tokens.Count -ge 3 -and $wordToComplete -like '-*') {
        $flags = @('-S','--control-socket','-n','--name','--token','--token-file','--timeout','--help')
        if ($tokens[2] -eq 'replace') { $flags += '--file' }
        $flags | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterName', $_)
        }
        return
    }
    $candidates = switch ($sub) {
        'image'      { @('ls','list','pull','rm','remove','rmi','inspect','tag','save','load','prune') }
        'volume'     { @('create','ls','list','inspect','compact','rm','remove','prune') }
        'system'     { @('info','df','prune') }
        'port'       { @('ls','list','add','rm','remove') }
        'net-policy' { @('get','replace') }
        'mount'      { @('ls','list','add','remount','rm','remove','serve') }
        'sandbox'    { @('inspect') }
        'completion' { @('bash','zsh','fish','powershell') }
        default      { @() }
    }
    if ($tokens.Count -eq 2 -or ($tokens.Count -eq 3 -and $wordToComplete -ne '')) {
        $candidates | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}
`
