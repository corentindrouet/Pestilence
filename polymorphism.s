section	.data

section	.text
	global	_start
	global	_byterpl
	global	_fn
	global	_stackdump
	global	_urand

;; -----------------------------------------------------------------------------
;; Junk instructions
;; -----------------------------------------------------------------------------
%define BYTERPL_MIN		0
%define BYTERPL_MAX		16

_bytes:
dd 0x90f63148,	; xor rsi, rsi
dd 0x90d23148,	; xor rdx, rdx
dd 0x90f23148,	; xor rdx, rsi
dd 0x90d63148,	; xor rsi, rdx
dd 0x90e6c148,	; shl rsi, 1
dd 0x90e2d148,	; shl rdx, 1
dd 0x90eed148,	; shr rsi, 1
dd 0x90ead148,	; shr rdx, 1
dd 0x90f62148,	; and rsi, rsi
dd 0x90d22148,	; and rdx, rdx
dd 0x90d62148,	; and rsi, rdx
dd 0x90f22148,	; and rdx, rsi
dd 0x909090fc,	; cld
dd 0x90d68948,	; mov rsi, rdx
dd 0x90f28948,	; mov rdx, rsi
dd 0x90f23948,	; cmp rdx, rsi
dd 0x90d63948	; cmp rsi, rdx

;; -----------------------------------------------------------------------------
;; Static strings
;; -----------------------------------------------------------------------------
_urandom:
.string db '/dev/urandom', 0

_hello:
.string db 'Hello World !', 0

;; -----------------------------------------------------------------------------
;; SYNOPSIS
;;		size_t	_fn(char *ptr)
;;
;; DESCRIPTION
;;		Returns the length in bytes of the string pointed by ptr.
;; ----------------------------------------------------------------------------
_fn:
.start:
	enter	16, 0
	nop
	nop
	nop
	nop
	xor		rcx, rcx
	nop
	nop
	nop
	nop
	mov		qword [rsp], rdi
	nop
	nop
	nop
	nop
	cmp		rdi, 0
	je		_fn.return
	jmp		_fn.loop
.loop:
	nop
	nop
	nop
	nop
	cmp		byte [rdi], 0
	je		_fn.return
	nop
	nop
	nop
	nop
	inc		rcx
	nop
	nop
	nop
	nop
	inc		rdi
	jmp		_fn.loop
.return:
	nop
	nop
	nop
	nop
	mov		rdi, qword [rsp]
	nop
	nop
	nop
	nop
	mov		rax, rcx
	leave
	ret
.end:

;; -----------------------------------------------------------------------------
;; SYNOPSIS
;;		uint64_t	_urand(uint64_t min, uint64_t max, uint64_t def)
;;
;; DESCRIPTION
;;		Returns an unsigned integer betwen min and max. If open /dev/urandom
;;		fails, the value returned will be computed according to def :
;;			if def < max
;;				return def + 1
;;			else if def == max
;;				return 0
;;
;; STACK USAGE
;;		rbp - 8		: fd
;;		rbp - 16	: return value
;;		rbp - 24	: min value
;;		rbp - 32	: max value
;; ----------------------------------------------------------------------------
_urand:
	enter	48, 0
	
	;; uint64_t a = min
	mov		qword [rbp - 24], rdi
	;; uint64_t b = max
	mov		qword [rbp - 32], rsi
	;; uint64_t c = def
	mov		qword [rbp - 40], rdx

_urand_open:
	;; int fd = open("/dev/urandom", O_RDONLY)
	mov		rax, 2
	lea		rdi, [rel _urandom]
	xor		rsi, rsi
	xor		rdx, rdx
	syscall

	;; if (fd == -1) return (-1)
	cmp		rax, -1
	jle		_urand_default
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
	cmp		rax, qword [rbp - 24]
	jl		_urand_read
	cmp		rax, qword [rbp - 32]
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
	jmp		_urand_end

_urand_default:
	;; if (def < max)
	mov		rax, qword [rbp - 40]
	cmp		rax, qword [rbp - 32]
	jl		_urand_default_plus
	jmp		_urand_default_zero

_urand_default_plus:
	;; return (def + 1)
	mov		rax, qword [rbp - 40]
	add		rax, 1
	jmp		_urand_end

_urand_default_zero:
	;; return (0)
	mov		rax, 0
	jmp		_urand_end

_urand_end:
	leave
	ret

;; -----------------------------------------------------------------------------
;; SYNOPSIS
;;		void	_byterpl(void *ptr, size_t len)
;;
;; DESCRIPTION
;;		It searches 4 NOPs (0x90) in a row into the buffer pointed by ptr and 
;;		replaces them randomly with the values from the _bytes dword array.
;;		The randomness of the values is ensured by _urand function which gets 
;;		its input from /dev/urandom.
;; ----------------------------------------------------------------------------
_byterpl:
.start:
	enter	32, 0
	push	rdi
	push	rsi
	push	r10

	xor		rax, rax
	mov		qword [rbp - 8], rax			; global offset
	mov		qword [rbp - 16], rax			; temporary offset
	mov		qword [rbp - 24], rax			; replace bytes offset

.loop:
	cmp		qword [rbp - 8], rsi			; did we go too far ?
	jge		_byterpl.end					; yeup, we're done
	
	cmp		byte [rdi], 0x90				; if we found a 0x90
	je		_byterpl.init					; check if we have 5 in a row

	inc		rdi								; move to the next byte
	inc		qword [rbp - 8]					; increment global offset
	
	jmp		_byterpl.loop					; check next byte

.init:
	xor		rcx, rcx						; clear counter
	mov		r10, rdi						; set up temporary pointer
	mov		rax, qword [rbp - 8]
	mov		qword [rbp - 16], rax

.check:
	cmp		qword [rbp - 16], rsi			; did we go too far ?
	jge		_byterpl.end					; yeup, we're done

	cmp		byte [r10], 0x90				; is the byte different from 0x90 ?
	jne		_byterpl.test					; yeup, check the counter

	inc		rcx								; increase counter
	inc		r10								; move to next byte
	inc		qword [rbp - 16]				; increase temporary counter
	jmp		_byterpl.check					; loop back

.test:
	cmp		rcx, 4							; is our counter up to 4 ?
	jge		_byterpl.replace				; great, replace at this offset
	inc		rdi								; move to next byte
	jmp		_byterpl.loop					; nope, back to main loop...

.replace:
	push	rdi								; save up
	push	rsi								; save up
	push	rdx								; save up
	mov		rdi, BYTERPL_MIN				; index min
	mov		rsi, BYTERPL_MAX				; index max
	mov		rdx, qword [rbp - 24]			; index def = current
	call	_urand							; call urand
	mov		qword [rbp - 24], rax			; store result
	pop		rdx								; restore
	pop		rsi								; restore
	pop		rdi								; restore

.insert:
	mov		rax, qword [rbp - 24]			; get the replacing bytes index
	lea		r11, [rel _bytes + rax * 4]		; get the value at this index
	mov		r11d, dword [r11]				; save it up

	mov		dword [rdi], r11d				; replace content of this offset

	add		rdi, 5							; move main pointer +5
	add		qword [rbp - 8], 5				; move global offset +5
	
	jmp		_byterpl.loop					; jump back to main loop...

.end:
	pop		r10
	pop		rsi
	pop		rdi
	leave
	ret

_start:
	enter	16, 0

;; -----------------------------------------------------------------------------
;; Copy the function _fn on stack
;; -----------------------------------------------------------------------------
_stackdump:
	;; Get code length
	lea		rdi, [rel _fn.start]
	lea		rsi, [rel _fn.end]
	sub		rsi, rdi
	mov		qword [rsp], rsi
	xor		rcx, rcx
	mov		rcx, rsi

	;; Setup destination pointer
	mov		rdi, rsp
	sub		rdi, rcx

	;; Setup source pointer
	lea		r10, [rel _fn.start]

.copy:
	;; If last byte break
	cmp		rcx, 0
	je		_replacebytes

	;; Copy byte from opcaodes to stack
	mov		al, byte [r10]
	mov		byte [rdi], al
	
	;; Move up pointers
	inc		r10
	inc		rdi
	
	;; Decrement counter
	dec		rcx
	
	;; Loop back
	jmp		_stackdump.copy
.end:

;; -----------------------------------------------------------------------------
;; Replace nopsleds on stack with junk instructions
;; -----------------------------------------------------------------------------
_replacebytes:
	;; Replace NOPs on stack
	mov		rsi, qword [rsp]
	mov		rdi, rsp
	sub		rdi, rsi
	mov		r10, qword [rsp]
	sub		rsp, r10
	call	_byterpl
	mov		rdi, rax
	add		rsp, r10

;; -----------------------------------------------------------------------------
;; Call function on stack
;; -----------------------------------------------------------------------------
_stackcall:
	;; Call function from stack
	mov		r10, qword [rsp]
	sub		rsp, r10
	lea		rdi, [rel _hello.string]
	call	rsp
	mov		rdi, rax
	add		rsp, r10

_end:
	leave
	mov		rax, 60
	syscall
