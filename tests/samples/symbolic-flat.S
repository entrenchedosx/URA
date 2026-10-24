/* Owned scalar dispatcher fixture. Assemble, inspect and emulate; never launch. */
.intel_syntax noprefix
.text
.globl ura_flattened
#ifndef _WIN32
.type ura_flattened,@function
#endif
ura_flattened:
#ifdef _WIN32
    mov eax, ecx
#else
    mov eax, edi
#endif
    mov ecx, 1
.Ldispatch:
    cmp ecx, 1
    je .Lcase1
    cmp ecx, 2
    je .Lcase2
    cmp ecx, 3
    je .Lcase3
    ret
.Lcase1:
    add eax, 7
    mov ecx, 2
    jmp .Ldispatch
.Lcase2:
    xor eax, 0x55
    mov ecx, 3
    jmp .Ldispatch
.Lcase3:
    ret
#ifndef _WIN32
.size ura_flattened,.-ura_flattened
#endif
