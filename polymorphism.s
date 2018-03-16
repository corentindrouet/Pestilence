section	.text
	global	_timestamp
	global	_prng
	global	_urand
	global	_byterpl

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
	db '/dev/urandom', 0

;; -----------------------------------------------------------------------------
;; NAME
;;		_timestamp
;;
;; SYNOPSIS
;;		int64_t		_timestamp(void)
;;
;; DESCRIPTION
;;		Returns the current timestamp on success, -1 otherwise.
;; -----------------------------------------------------------------------------
_timestamp:
	enter	16, 0

	;; int ret = gettimeofday(&rsp)
	mov		rax, 96
	lea		rdi, [rsp]
	mov		rsi, 0
	syscall
	
	;; if (ret == -1) return (-1)
	cmp		rax, -1
	je		_timestamp_end
	
	;; else return (*rsp)
	mov		rax, qword [rsp]

_timestamp_end:
	leave
	ret

;; -----------------------------------------------------------------------------
;; NAME
;;		_prng
;;
;; SYNOPSIS
;;		uint64_t	_prng(uint64_t seed, uint64_t max)
;;
;; DESCRIPTION
;;		Computes a pseudo-random number based on a seed with the following
;;		formula : ((8253729 * seed + 2396403)) % max
;; -----------------------------------------------------------------------------
_prng:
	enter	0, 0
	mov		rax, 8253729
	mul		rdi
	add		rax, 2396403
	mov		rdi, rsi
	div		rdi
	mov		rax, rdx
	leave
	ret

;; -----------------------------------------------------------------------------
;; NAME
;;		_urand
;;
;; SYNOPSIS
;;		int64_t		_urand(uint64_t min, uint64_t max, uint64_t seed)
;;
;; DESCRIPTION
;;		Returns an unsigned integer betwen min and max.
;;		At first it will try to open /dev/urandom and read bytes for as long as
;;		the number read is out of range.
;;		If the first method fails, it will falls back to a pseudo-random number
;;		generator based on the seed + timestamp.
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
	;; uint64_t c = seed
	mov		qword [rbp - 40], rdx
	;; uint64_t e = 0
	mov		qword [rbp - 48], 0

_urand_open:
	;; int fd = open("/dev/urandom", O_RDONLY)
	mov		rax, 2
	lea		rdi, [rel _urandom]
	xor		rsi, rsi
	xor		rdx, rdx
	syscall

	;; if (fd == -1) return (_prng())
	cmp		rax, -1
	jle		_urand_prng
	mov		qword [rbp - 8], rax

_urand_read:
	;; ssize_t r = read(1, &i, 1)
	mov		rax, 0
	mov		rdi, qword [rbp - 8]
	lea		rsi, [rbp - 16]
	mov		rdx, 1
	syscall
	
	;; if (r <= 0) close(fd)
	mov		qword [rbp - 48], rax
	cmp		rax, 0
	jle		_urand_close

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

	cmp		qword [rbp - 48], 0
	jle		_urand_prng

_urand_return:
	;; return (i)
	mov		al, byte [rbp - 16]
	movzx	rax, al
	jmp		_urand_end

_urand_prng:
	;; def += _timestamp()
	call	_timestamp
	mov		rdi, rax
	add		rdi, qword [rbp - 40]

	;; _prng(def, max)
	mov		rsi, qword [rbp - 32]
	call	_prng

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
	enter	32, 0
	push	rdi
	push	rsi
	push	r10

	xor		rax, rax
	mov		qword [rbp - 8], rax			; global offset
	mov		qword [rbp - 16], rax			; temporary offset
	mov		qword [rbp - 24], rax			; backup value for PRNG

_byterpl_loop:
	cmp		qword [rbp - 8], rsi			; did we go too far ?
	jge		_byterpl_end					; yeup, we're done
	
	cmp		byte [rdi], 0x90				; if we found a 0x90
	je		_byterpl_init					; check if we have 5 in a row

	inc		rdi								; move to the next byte
	inc		qword [rbp - 8]					; increment global offset
	
	jmp		_byterpl_loop					; check next byte

_byterpl_init:
	xor		rcx, rcx						; clear counter
	mov		r10, rdi						; set up temporary pointer
	mov		rax, qword [rbp - 8]
	mov		qword [rbp - 16], rax

_byterpl_check:
	cmp		qword [rbp - 16], rsi			; did we go too far ?
	jge		_byterpl_end					; yeup, we're done

	cmp		byte [r10], 0x90				; is the byte different from 0x90 ?
	jne		_byterpl_test					; yeup, check the counter

	inc		rcx								; increase counter
	inc		r10								; move to next byte
	inc		qword [rbp - 16]				; increase temporary counter
	jmp		_byterpl_check					; loop back

byterpl_test:
	cmp		rcx, 4							; is our counter up to 4 ?
	jge		_byterpl_replace				; great, replace at this offset
	inc		rdi								; move to next byte
	jmp		_byterpl_loop					; nope, back to main loop...

_byterpl_replace:
	push	rdi								; save up
	push	rsi								; save up
	push	rdx								; save up

	add		qword [rbp - 24], 3				; increment by 3 the PRNG def value
	mov		rdi, BYTERPL_MIN				; minimum byte array index
	mov		rsi, BYTERPL_MAX				; maximum byte array index
	mov		rdx, qword [rbp - 24]			; index def = current
	call	_urand							; call urand
	
	mov		qword [rbp - 24], rax			; store result
	cmp		rax, -1							; if _urand returned -1, we need to get the fuck out
	je		_byterpl_end					; get the fuck out then ...
	
	pop		rdx								; restore
	pop		rsi								; restore
	pop		rdi								; restore

_byterpl_insert:
	mov		rax, qword [rbp - 24]			; get the replacing bytes index
	lea		r11, [rel _bytes + rax * 4]		; get the value at this index
	mov		r11d, dword [r11]				; save it up

	mov		dword [rdi], r11d				; replace content of this offset

	add		rdi, 5							; move main pointer +5
	add		qword [rbp - 8], 5				; move global offset +5
	
	jmp		_byterpl_loop					; jump back to main loop...

_byterpl_end:
	mov		rax, qword [rbp - 24]
	pop		r10
	pop		rsi
	pop		rdi
	leave
	ret
