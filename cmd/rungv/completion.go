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

    local top_cmds="run pull images rmi inspect tag save load login logout image volume system info checkpoint restore version license completion help"
    local image_cmds="ls list pull rm remove rmi inspect tag save load prune"
    local volume_cmds="create ls list inspect rm remove prune"
    local system_cmds="info df prune"
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
        completion)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${shells}" -- "${cur}") )
                return 0
            fi
            ;;
        run)
            case "${prev}" in
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
            esac
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=( $(compgen -W "-i -t -w --workdir -workspace -v --volume --mount -p -P -e --env-file -u --user -m --memory --cpus --net --backend --platform --pull --entrypoint --rm -cache-dir --help" -- "${cur}") )
                return 0
            fi
            ;;
    esac
}
complete -F _rungv_completions rungv
`

const zshCompletionScript = `#compdef rungv

_rungv() {
    local -a top_cmds image_cmds volume_cmds system_cmds shells
    top_cmds=(
        'run:Create and run a sandboxed Linux guest'
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
        'checkpoint:Checkpoint a running sandbox'
        'restore:Restore a sandbox from a checkpoint directory'
        'version:Print rungv version metadata'
        'license:Print third-party license notices'
        'completion:Print shell completion scripts'
        'help:Print command usage'
    )
    image_cmds=(ls list pull rm remove rmi inspect tag save load prune)
    volume_cmds=(create ls list inspect rm remove prune)
    system_cmds=(info df prune)
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
                '*-p[Publish guest port to host]:port:' \
                '-P[Publish all exposed image ports]' \
                '*-e[Set guest environment variable]:env:' \
                '*--env-file[Read environment variables from file]:file:_files' \
                '-u[Guest user or UID:GID]:user:' \
                '-m[Guest memory limit]:bytes:' \
                '--cpus[Guest CPU quota]:cpus:' \
                '--net[Network mode]:mode:(nat wg none)' \
                '--backend[Execution backend]:backend:(auto whpx hvf systrap)' \
                '--platform[Target image platform]:platform:(linux/amd64 linux/arm64)' \
                '--pull[Image pull policy]:policy:(missing always never)'
            ;;
    esac
}

compdef _rungv rungv
`

const fishCompletionScript = `# fish completion for rungv
complete -c rungv -f

set -l __rungv_top_cmds run pull images rmi inspect tag save load login logout image volume system info checkpoint restore version license completion help

complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a run -d "Run a command in a new sandbox"
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
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a checkpoint -d "Checkpoint a running sandbox"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a restore -d "Restore a checkpointed sandbox"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a version -d "Print version information"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a license -d "Print license notices"
complete -c rungv -n "not __fish_seen_subcommand_from $__rungv_top_cmds" -a completion -d "Generate shell completion script"

complete -c rungv -n "__fish_seen_subcommand_from image; and not __fish_seen_subcommand_from ls list pull rm remove rmi inspect tag save load prune" -a "ls pull rm inspect tag save load prune"
complete -c rungv -n "__fish_seen_subcommand_from volume; and not __fish_seen_subcommand_from create ls list inspect rm remove prune" -a "create ls inspect rm prune"
complete -c rungv -n "__fish_seen_subcommand_from system; and not __fish_seen_subcommand_from info df prune" -a "info df prune"
complete -c rungv -n "__fish_seen_subcommand_from completion" -a "bash zsh fish powershell"
`

const powershellCompletionScript = `# PowerShell completion for rungv
Register-ArgumentCompleter -Native -CommandName rungv -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $tokens = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }
    $topCmds = @('run','pull','images','rmi','inspect','tag','save','load','login','logout','image','volume','system','info','checkpoint','restore','version','license','completion','help')

    if ($tokens.Count -le 1 -or ($tokens.Count -eq 2 -and $wordToComplete -ne '')) {
        $topCmds | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        return
    }

    $sub = $tokens[1]
    $candidates = switch ($sub) {
        'image'      { @('ls','list','pull','rm','remove','rmi','inspect','tag','save','load','prune') }
        'volume'     { @('create','ls','list','inspect','rm','remove','prune') }
        'system'     { @('info','df','prune') }
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
