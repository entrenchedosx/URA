/* Owned freestanding cross-processor semantic fixtures. No host APIs or runtime. */
#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif
#define FN EXPORT __attribute__((noinline))
// Scalar word follows the target register width.
#if __SIZEOF_POINTER__ == 4
typedef unsigned int u64;
typedef int signed_word;
#else
typedef unsigned long long u64;
typedef long long signed_word;
#endif
typedef unsigned int u32;
FN u64 ura_scalar(u64 a, u64 b) { return (a + b * 3) ^ 0x5a; }
FN u64 ura_select(signed_word a, signed_word b) { return a < b ? (u64)a + 7 : (u64)b - 9; }
FN u32 ura_width(u32 a, u32 b) { return (a + b) ^ (a >> 3); }
FN u64 ura_loop(u64 a, u64 n) { for (u64 i=0; i<n; ++i) a = (a ^ i) + 3; return a; }
FN u64 ura_pointer(u64 *p, u64 a) { u64 old = *p; *p = old + a; return old ^ a; }
FN u64 ura_stack(u64 a) { volatile u64 values[3]; values[0]=a; values[1]=a+5; values[2]=values[0]^values[1]; return values[2]; }
FN u64 ura_nested(u64 a, u64 b) { return ura_scalar(a,b) + a; }
static const u64 table[4] = {17,29,41,53};
FN u64 ura_literal(u64 n) { return table[n & 3]; }
FN u64 ura_div(u64 a, u64 b) { return a/b; }

FN u64 ura_stack_args(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,u64 i) { return a+b+c+d+e+f+g+h+i; }
