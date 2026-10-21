/* Original deterministic compiler fixture, distributed under URA's MIT license.
 * These programs are inspected statically; verification never executes them. */
#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
#define NOINLINE __attribute__((noinline))
volatile int switch_state;
EXPORT NOINLINE int switch_case0(int x) { switch_state += x + 3; return switch_state; }
EXPORT NOINLINE int switch_case1(int x) { switch_state ^= x + 7; return switch_state; }
EXPORT NOINLINE int switch_case2(int x) { switch_state -= x + 11; return switch_state; }
EXPORT NOINLINE int switch_case3(int x) { switch_state |= x + 17; return switch_state; }
EXPORT NOINLINE int switch_case4(int x) { switch_state &= x + 23; return switch_state; }
EXPORT NOINLINE int switch_case5(int x) { switch_state += x * 31; return switch_state; }
EXPORT NOINLINE int switch_sample(unsigned index, int value) {
    switch (index) {
    case 0: return switch_case0(value);
    case 1: return switch_case1(value);
    case 2: return switch_case2(value);
    case 3: return switch_case3(value);
    case 4: return switch_case4(value);
    case 5: return switch_case5(value);
    default: return -1;
    }
}
