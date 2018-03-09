%define FT_STRLEN_S

section .text
	global	_ft_strlen

_ft_strlen:
	enter	0, 0
	push	rdi
	xor		rax, rax
	xor		rcx, rcx
	cmp		rdi, 0
	je		_ft_strlen_end

_ft_strlen_loop:
	cmp		byte [rdi], 0
	je		_ft_strlen_end
	inc		rcx
	inc		rdi
	jmp		_ft_strlen_loop

_ft_strlen_end:
	mov		rax, rcx
	pop		rdi
	leave
	ret

%undef FT_STRLEN_S
