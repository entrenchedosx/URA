// Owned freestanding regression corpus. Inspected statically, never launched.
using u64 = unsigned long long;
#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C" __attribute__((visibility("default")))
#endif
struct Record { u64 count; u64 value; };
EXPORT __attribute__((noinline)) u64 cpp_scalar(u64 a, u64 b) {
    return ((a ^ b) + 7) & 255;
}
EXPORT __attribute__((noinline)) u64 cpp_record(Record *p, u64 value) {
    p->value += value;
    return p->value;
}
EXPORT __attribute__((noinline)) u64 cpp_branch(u64 a, u64 b) {
    return a < b ? a + 1 : b - 2;
}
EXPORT __attribute__((noinline)) u64 cpp_nested(u64 n) {
    volatile u64 sum = 0;
    for (u64 i=0; i<n; i=i+1) {
        for (u64 j=0; j<i; j=j+1) sum=sum+j;
    }
    return sum;
}
EXPORT __attribute__((noinline)) u64 cpp_switch(u64 n) {
    switch(n) {case 0:return 17;case 1:return 3;case 2:return 91;
    case 3:return 6;case 4:return 55;default:return 0;}
}
struct Counter {
    u64 n;
    __attribute__((noinline)) u64 step(u64 value) {n += value;return n;}
};
EXPORT __attribute__((noinline)) u64 cpp_member(Counter *p,u64 value) {
    return p->step(value);
}
