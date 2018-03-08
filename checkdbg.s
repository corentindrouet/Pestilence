%define CHECKDBG_S

section	.text
	global	_checkdbg
	%include "pestilence.lst"

;; -----------------------------------------------------------------------------------
;; NAME
;;		_checkdbg
;;
;; SYNOPSIS
;;		int		_checkdbg(void)
;;
;; DESCRIPTION
;;		Checks whether a tracing session exists for this process. If a session is
;;		found, this function returns 1, 0 otherwise.
;; -----------------------------------------------------------------------------------
_checkdbg:
	;; Save up registers
	enter	0, 0
	push	rdi
	push	rsi
	push	rdx
	push	r10

	;; Calling ptrace(PTRACE_TRACEME)
	mov		rax, sys_ptrace
	mov		rdi, PTRACE_TRACEME
	mov		rsi, 0
	mov		rdx, 0
	mov		r10, 0
	syscall

	;; On error, a tracing session is already ongoing
	cmp		rax, -1
	je		_checkdbg_false
	jmp		_checkdbg_true

_checkdbg_true:
	mov		rax, 0
	jmp		_checkdbg_end

_checkdbg_false:
	mov		rax, 1
	jmp		_checkdbg_end

_checkdbg_end:
	;; Restore registers
	pop		r10
	pop		rdx
	pop		rsi
	pop		rdi
	leave
	ret

%undef CHECKDBG_S
