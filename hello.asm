.386
.model flat, stdcall
option casemap :none
 
include \masm32\include\msvcrt.inc
include \masm32\include\kernel32.inc
 
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\msvcrt.lib
 
.data
    hello db "Hello World!", 15
    size1 dd 12
 
.code
start:
    mov eax, size1
    push eax
    push offset hello
    push 1
    call crt__write
 
    push 0
    call ExitProcess
end start
