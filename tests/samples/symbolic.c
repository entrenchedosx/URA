/* URA-owned fixed-width symbolic-analysis corpus. No host OS APIs or runtime. */
typedef unsigned int u32;
#if defined(_WIN32)
#define EXPORT __declspec(dllexport) __declspec(noinline)
#else
#define EXPORT __attribute__((visibility("default"), noinline))
#endif
EXPORT u32 ura_opaque_even(u32 x) {
    volatile u32 y = x;
    if ((y * (y + 1u) & 1u) != 0u) return 0xfbad1234u;
    return (x ^ 0x12345678u) + 17u;
}
EXPORT u32 ura_opaque_odd(u32 x) {
    volatile u32 y = x | 1u;
    if ((y * y & 1u) == 0u) return 0xbad56789u;
    return x + 23u;
}
EXPORT u32 ura_nonopaque(u32 x) {
    if ((x * (x + 2u) & 1u) != 0u) return x ^ 0x55u;
    return x + 3u;
}
EXPORT u32 ura_wrap(u32 x) {
    if (x + 1u > x) return x + 11u;
    return x - 9u;
}
EXPORT u32 ura_signed(u32 x) {
    if ((int)x < 0) return x ^ 0x87654321u;
    return x + 31u;
}
EXPORT u32 ura_alias(u32 *p, u32 *q, u32 x) {
    *p = x;
    *q = x + 1u;
    return *p;
}
EXPORT u32 ura_loop(u32 x) {
    u32 value = x;
    for (u32 i = 0; i < (x & 3u) + 1u; ++i) value = value * 3u + i;
    return value;
}
EXPORT u32 ura_complement(u32 x) { return ~x; }
EXPORT u32 ura_negate(u32 x) { return 0u - x; }
