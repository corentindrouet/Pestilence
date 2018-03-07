;; ---------------------------------------------------
;; size_t	_file_size(int fd)
;; ---------------------------------------------------

section .text
	global	_file_size

%define SEEK_SET	0x0
%define SEEK_END	0x2

%define sys_lseek	8

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
