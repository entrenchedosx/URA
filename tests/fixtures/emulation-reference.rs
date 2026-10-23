//! Owned, windowless x64 hardware oracle; built afresh by the semantic test.
use std::arch::global_asm;
global_asm!(r#"
.global ura_emu_math
ura_emu_math:
    mov eax, ecx
    imul eax, edx
    sar eax, 3
    ror eax, cl
    cmp eax, edx
    cmovl eax, edx
    ret
"#);
extern "C" {fn ura_emu_math(a:u32,b:u32)->u32;}
fn main(){for(a,b)in [(0,0),(1,3),(31,7),(0x80000000,3),(0x7fffffff,0x80000001),(255,0xffffffff)]{println!("{} {} {}",a,b,unsafe{ura_emu_math(a,b)});}}
