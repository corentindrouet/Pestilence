section	.text
	global	_urand

_urandom:
	db '/dev/urandom', 0

_urand:
	enter	16, 0

_urand_open:
	;; int fd = open("/dev/urandom", O_RDONLY)
	mov		rax, 2
	lea		rdi, [rel _urandom]
	xor		rsi, rsi
	xor		rdx, rdx
	syscall
	
	;; if (fd == -1) return (-1)
	cmp		rax, -1
	jle		_urand_end
	mov		qword [rbp - 8], rax

_urand_read:
	;; read(1, &i, 1)
	mov		rax, 0
	mov		rdi, qword [rbp - 8]
	lea		rsi, [rbp - 16]
	mov		rdx, 1
	syscall

	;; if (i >= 0 && i <= 20)
	mov		al, byte [rbp - 16]
	movzx	rax, al
	cmp		rax, 0
	jl		_urand_read
	cmp		rax, 20
	jg		_urand_read

_urand_close:
	;; close(fd)
	mov		rax, 3
	mov		rdi, qword [rbp - 8]
	syscall

_urand_return:
	;; return (i)
	mov		al, byte [rbp - 16]
	movzx	rax, al

_urand_end:
	leave
	ret
