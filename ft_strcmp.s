section .text
	global	_ft_strcmp
	extern	_ft_strlen

;; -----------------------------------------------------------------------------------
;; int		_ft_strcmp(const char *s1, const char *s2)
;; -----------------------------------------------------------------------------------
_ft_strcmp:
	enter	16, 0
	push	rdi
	push	rsi

	xor		rax, rax
	mov		qword [rsp], rdi
	mov		qword [rsp + 8], rsi

	call	_ft_strlen
	mov		rcx, rax

	mov		rdi, rsi
	call	_ft_strlen
	cmp		rcx, rax
	jne		_ft_strcmp_error

	xor		rcx, rcx
	mov		rdi, qword [rsp]
	mov		rsi, qword [rsp + 8]

_ft_strcmp_loop:
	cmp		rcx, rax
	je		_ft_strcmp_end

	mov		cl, byte [rdi + rcx]
	cmp		cl, byte [rsi + rcx]
	jne		_ft_strcmp_error

	inc		rcx
	jmp		_ft_strcmp_loop

_ft_strcmp_error:
	mov		rax, 1

_ft_strcmp_end:
	pop		rsi
	pop		rdi
	leave
	ret
