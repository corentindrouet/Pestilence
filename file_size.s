%define FILE_SIZE_S

section .text
	global	_file_size
	%include "pestilence.lst"

;; -----------------------------------------------------------------------------------
;; NAME
;;		_file_size
;;
;; SYNOPSIS
;;		size_t	_file_size(int fd)
;;
;; DESCRIPTION
;;		Returns the size in bytes of the file pointed by fd.
;; -----------------------------------------------------------------------------------
_file_size:
	enter	0, 0
	push	rdi
	push	rsi
	push	rdx
	xor		rax, rax

	mov		rax, sys_lseek
	mov		rsi, 0
	mov		rdx, SEEK_SET
	syscall

	mov		rax, sys_lseek
	mov		rsi, 0
	mov		rdx, SEEK_END
	syscall

	mov		rcx, rax

	mov		rax, sys_lseek
	mov		rsi, 0
	mov		rdx, SEEK_SET
	syscall
	
	mov		rax, rcx

	pop		rdx
	pop		rsi
	pop		rdi
	leave
	ret

%undef FILE_SIZE_S
