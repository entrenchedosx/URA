.text
.globl _patch_entry
_patch_entry:
movl $0x12345678, %eax
ret
movl $0x2a, %eax
ret
.data
.long 0x12345678
.bss
.space 64
