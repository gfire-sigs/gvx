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

//go:build darwin && amd64

#include "textflag.h"

TEXT ·sandboxInitWithParametersTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_sandbox_init_with_parameters(SB)

TEXT ·addrOfSandboxInitWithParameters(SB),NOSPLIT,$0-8
	LEAQ	·sandboxInitWithParametersTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sandboxFreeErrorTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_sandbox_free_error(SB)

TEXT ·addrOfSandboxFreeError(SB),NOSPLIT,$0-8
	LEAQ	·sandboxFreeErrorTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sandboxExtIssueFileTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_sandbox_extension_issue_file(SB)

TEXT ·addrOfSandboxExtIssueFile(SB),NOSPLIT,$0-8
	LEAQ	·sandboxExtIssueFileTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sandboxExtConsumeTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_sandbox_extension_consume(SB)

TEXT ·addrOfSandboxExtConsume(SB),NOSPLIT,$0-8
	LEAQ	·sandboxExtConsumeTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sandboxExtReleaseTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_sandbox_extension_release(SB)

TEXT ·addrOfSandboxExtRelease(SB),NOSPLIT,$0-8
	LEAQ	·sandboxExtReleaseTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·libcFreeTrampoline(SB),NOSPLIT,$0-0
	JMP	libc_free(SB)

TEXT ·addrOfLibcFree(SB),NOSPLIT,$0-8
	LEAQ	·libcFreeTrampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET
