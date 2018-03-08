section	.text
	global	_start

%define SYS_OPEN			2
%define SYS_CLOSE			3
%define SYS_GETTIMEOFDAY	96

_target:
	.string db 'target', 0

_crypt:
	enter	0, 0
_crypt_end:
	leave
	ret

_crypt1:
	enter	0, 0
_crypt1_end:
	leave
	ret

_cyrpt2:
	enter	0, 0
_cyrpt2_end:
	leave
	ret

;; -------------------------------------------------------
;; void		_injector(void *start_ptr, void *end_ptr) 
;; -------------------------------------------------------
_injector:
	enter	16, 0

_injector_open:
	;; Open target file
	mov		rax, SYS_OPEN
	lea		rdi, [rel _target.string]
	mov		rsi, 578
	mov		rdx, 0666
	syscall
	cmp		rax, -1
	je		_injector_end
	mov		qword [rsp], rax

_injector_write:

_injector_close:
	mov		rax, SYS_CLOSE
	mov		rdi, qword [rsp]
	syscall

_injector_end:
	leave
	ret

;; -------------------------------------------------------
;; void		_selector(void)
;; -------------------------------------------------------
_selector:
	enter	16, 0

	;; Select depacker based on gettimeofday
	mov		rax, SYS_GETTIMEOFDAY
	lea		rdi, [rsp]
	mov		rsi, 0
	syscall
	cmp		rax, -1
	je		_selector_default
	xor		rdx, rdx
	mov		rax, qword [rsp]
	mov		rcx, 10
	div		rcx
	mov		rax, rdx

	cmp		rax, 1
	je		_selector_1
	cmp		rax, 2
	je		_selector_2

_selector_default:
	lea		rdi, [rel _crypt]
	lea		rsi, [rel _crypt_end + 2]
	call	_injector

_selector_1:
	lea		rdi, [rel _crypt1]
	lea		rsi, [rel _crypt1_end + 2]
	jmp		_selector_end

_selector_2:
	lea		rdi, [rel _crypt2]
	lea		rsi, [rel _crypt2_end + 2]
	jmp		_selector_end

_selector_end:
	leave
	ret

_start:
	enter	0, 0

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
