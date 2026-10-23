.text
.global ura_udiv
.type ura_udiv, %function
ura_udiv:
    udiv x0, x0, x1
    ret
.size ura_udiv, .-ura_udiv
.global ura_sdiv
.type ura_sdiv, %function
ura_sdiv:
    sdiv x0, x0, x1
    ret
.size ura_sdiv, .-ura_sdiv
.global ura_flags
.type ura_flags, %function
ura_flags:
    adds x0, x0, x1
    cset x2, cs
    cset x3, vs
    cset x4, eq
    cset x5, mi
    ret
.size ura_flags, .-ura_flags
.global ura_rotate
.type ura_rotate, %function
ura_rotate:
    ror x0, x0, x1
    ret
.size ura_rotate, .-ura_rotate
.global ura_wide
.type ura_wide, %function
ura_wide:
    movz x0, #0xabcd, lsl #48
    movk x0, #0x1234, lsl #16
    ret
.size ura_wide, .-ura_wide
.global ura_bad_alias
.type ura_bad_alias, %function
ura_bad_alias:
    .inst 0xb8404400 // constrained/unpredictable alias: decoder-only rejection fixture
    ret
.size ura_bad_alias, .-ura_bad_alias
.global ura_bad_pair
.type ura_bad_pair, %function
ura_bad_pair:
    .inst 0xa9400020 // constrained/unpredictable duplicate load destinations
    ret
.size ura_bad_pair, .-ura_bad_pair
