section	.text
	global	_start

%define SYS_OPEN			2
%define SYS_CLOSE			3
%define SYS_GETTIMEOFDAY	96

_target:
	.string db 'target', 0

_s:
	.string db 'KET9zNHsNV', 0
	.length equ $ - _s.string

_s1:
	.string db 'OPErj77fXt', 0
	.length equ $ - _s1.string

_s2:
	.string db 'eW8I3eDM5b', 0
	.length equ $ - _s2.string

_s3:
	.string db '8GVmZCGhly', 0
	.length equ $ - _s3.string

_s4:
	.string db 'HWlFJN8IEQ', 0
	.length equ $ - _s4.string

_s5:
	.string db 'sun6xlBzGI', 0
	.length equ $ - _s5.string

_crypt:
	enter	0, 0
	mov		rax, 1
	mov		rdi, 1
	lea		rsi, [rel _s.string]
	mov		rdx, _s.length
_crypt_end:
	leave
	ret

_crypt1:
	enter	0, 0
	mov		rax, 1
	mov		rdi, 1
	lea		rsi, [rel _s1.string]
	mov		rdx, _s1.length
_crypt1_end:
	leave
	ret

_crypt2:
	enter	0, 0
	mov		rax, 1
	mov		rdi, 1
	lea		rsi, [rel _s2.string]
	mov		rdx, _s2.length
_crypt2_end:
	leave
	ret

_crypt3:
	enter	0, 0
	mov		rax, 1
	mov		rdi, 1
	lea		rsi, [rel _s3.string]
	mov		rdx, _s3.length
_crypt3_end:
	leave
	ret

_crypt4:
	enter	0, 0
	mov		rax, 1
	mov		rdi, 1
	lea		rsi, [rel _s4.string]
	mov		rdx, _s4.length
_crypt4_end:
	leave
	ret

_crypt5:
	enter	0, 0
	mov		rax, 1
	mov		rdi, 1
	lea		rsi, [rel _s5.string]
	mov		rdx, _s5.length
_crypt5_end:
	leave
	ret

;; -------------------------------------------------------
;; void		_injector(void *ptr, size_t len) 
;; -------------------------------------------------------
_injector:
	enter	32, 0

	;; Save
	mov		qword [rsp], rdi
	mov		qword [rsp + 8], rsi

_injector_open:
	;; Open target file
	mov		rax, SYS_OPEN
	lea		rdi, [rel _target.string]
	mov		rsi, 578
	mov		rdx, 0666
	syscall
	cmp		rax, -1
	je		_injector_end
	mov		qword [rsp + 16], rax

_injector_write:
	;; Write into target file
	mov		rax, 1
	mov		rdi, qword [rsp + 16]
	mov		rsi, qword [rsp]
	mov		rdx, qword [rsp + 8]
	syscall

_injector_close:
	;; Close fd
	mov		rax, SYS_CLOSE
	mov		rdi, qword [rsp + 16]
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
	
	;; If it failed, get default encryptor
	cmp		rax, -1
	je		_selector_default

	;; Get the last number of the timestamp
	xor		rdx, rdx
	mov		rax, qword [rsp]
	mov		rcx, 10
	div		rcx
	mov		rax, rdx

	;; If (number >= 1 && number <= totalNumberOfCryptors)
	cmp		rax, 1
	jl		_selector_default
	cmp		rax, 5
	jg		_selector_default
	jmp		_selector_number

_selector_default:
	;; Get the first cryptor
	lea		rdi, [rel _crypt]
	
	;; Get its size
	lea		rsi, [rel _crypt_end + 2]
	sub		rsi, rdi

	;; Inject it into file
	call	_injector
	jmp		_selector_end

_selector_number:
	;; Get the size of the cryptor
	lea		rdi, [rel _crypt]
	lea		rsi, [rel _crypt_end + 2]
	sub		rsi, rdi
	mov		rcx, rsi
	
	;; Multiply the cryptor by the number of the cryptor selected
	mul		rcx

	;; Fetch the body of the cryptor located at this address
	lea		rdi, [rel _crypt + rax]
	
	;; Inject it into file
	call	_injector
	jmp		_selector_end

_selector_end:
	leave
	ret

_start:
	enter	0, 0
	call	_selector
	leave
	mov		rax, 60
	mov		rdi, 0
	syscall
