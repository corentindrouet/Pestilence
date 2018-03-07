section	.text

global	_checkdbg

;; -----------------------------------------------------------------------------------
;; DEBUG
;; -----------------------------------------------------------------------------------
_debug_dbgin:
	.string db 'Tracing session detected. Exiting !', 10, 0
	.length equ $ - _debug_dbgin.string

_debug_dbgout:
	.string db 'No tracing session detected...', 10, 0
	.length equ $ - _debug_dbgout.string

_pdebug_dbgin:
	enter	0, 0
	mov		rax, 1
	mov		rdi, 1
	lea		rsi, [rel _debug_dbgin.string]
	mov		rdx, _debug_dbgin.length
	syscall
	leave
	ret

_pdebug_dbgout:
	enter	0, 0
	mov		rax, 1
	mov		rdi, 1
	lea		rsi, [rel _debug_dbgout.string]
	mov		rdx, _debug_dbgout.length
	syscall
	leave
	ret

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
	enter	0, 0
	push	rdi
	push	rsi
	push	rdx
	push	r10

	;; Calling ptrace(PTRACE_TRACEME)
	mov		rax, 101
	mov		rdi, 0
	mov		rsi, 0
	mov		rdx, 0
	mov		r10, 0
	syscall

	;; On error, a tracing session is already ongoing
	cmp		rax, -1
	je		_checkdbg_false
	jmp		_checkdbg_true

_checkdbg_true:
	;; Debug
	call	_pdebug_dbgout
	
	;; Return value
	mov		rax, 0
	jmp		_checkdbg_end

_checkdbg_false:
	;; Debug
	call	_pdebug_dbgin
	
	;; Return value
	mov		rax, 1
	jmp		_checkdbg_end

_checkdbg_end:
	pop		r10
	pop		rdx
	pop		rsi
	pop		rdi
	leave
	ret
