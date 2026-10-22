/* Independently compiled, freestanding semantic regression inputs. Never run
 * as native executables by the tests. Windows LLP64/ELF LP64 share this u64. */
typedef unsigned long long u64;
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif
EXPORT __attribute__((noinline)) u64 semantic_sum(u64 a, u64 b) {
    return a + b + 3;
}
EXPORT __attribute__((noinline)) u64 semantic_memory(u64 *p, u64 value) {
    *p += value;
    return *p;
}
EXPORT __attribute__((noinline)) u64 semantic_loop(u64 count) {
    volatile u64 sum = 0;
    while (count) {
        sum += count;
        count -= 3;
        if (count > 128) break;
    }
    return sum;
}
