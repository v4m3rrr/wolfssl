#include <wolfssl/tls_probe.h>

uint64_t tls_prof_cyc[P_MAX];
uint32_t tls_prof_cnt[P_MAX];
uint32_t tls_prof_ccounts[P_MAX];

uint32_t tls_ccount(void)
{
#if defined(__XTENSA__)
    uint32_t c;
    __asm__ __volatile__("rsr %0, ccount" : "=r"(c));
    return c;
#elif defined(__riscv)
    uint32_t c;
    __asm__ __volatile__("csrr %0, mcycle" : "=r"(c));
    return c;
#else
    return 0;
#endif
}
