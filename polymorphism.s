section	.data

;; -----------------------------------------------------------------------------
;; Junk instructions
;; -----------------------------------------------------------------------------
_bytes:
	dd 0x48f63148, 0x4dd23148, 0x48d2314d

section	.text
	global	_start
	global	_byterpl
	global	_fn
	global	_stackdump

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
	nop
	xor		rcx, rcx
	nop
	nop
	nop
	nop
	nop
	mov		qword [rsp], rdi
	nop
	nop
	nop
	nop
	nop
	cmp		rdi, 0
	je		_fn.return
.loop:
	nop
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
	nop
	inc		rcx
	nop
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
	nop
	mov		rdi, qword [rsp]
	nop
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
;;		void	_byterpl(void *ptr, size_t len)
;;
;; DESCRIPTION
;;		This function searches into the buffer pointed by ptr 5 NOPs (0x90)
;;		in a row and replaces them with the values from a dword array.
;;
;; NOTES
;;		For now, it doesn't randomise shit ...
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
	cmp		rcx, 5							; is our counter up to 5 ?
	jge		_byterpl.replace				; great, replace at this offset
	inc		rdi								; move to next byte
	jmp		_byterpl.loop					; nope, back to main loop...

.replace:
	cmp		qword [rbp - 24], 2				; did we reach the last index of the replacing bytes ?
	je		_byterpl.setzero				; if yes reset index to 0
	jmp		_byterpl.setplus				; if no increment to the next one

.setzero:
	mov		qword [rbp - 24], 0
	je		_byterpl.insert

.setplus:
	add		qword [rbp - 24], 1
	je		_byterpl.insert

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
