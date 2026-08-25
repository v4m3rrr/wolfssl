#ifndef _TLS_PROBE_H_
#define _TLS_PROBE_H_

#include "wolfssl/wolfcrypt/logging.h"

uint32_t tls_ccount(void);

typedef enum {
    P_CH_SEND, P_SH_PROC, P_EE_PROC, P_CERT_PROC, P_CR_PROC,P_CV_PROC,
    P_FIN_PROC, P_CERT_SEND, P_CV_SEND,P_FIN_SEND, P_KEYSCHED_HS,
    P_KEYSCHED_APP,P_DECRYPT, P_ENCRYPT, P_MAX
} tls_probe_id_t;

#if defined(TLS_PROFILE) && TLS_PROFILE

extern uint64_t tls_prof_cyc[P_MAX];
extern uint32_t tls_prof_cnt[P_MAX];
extern uint32_t tls_prof_ccounts[P_MAX];

#define TLS_PROBE_RESET(id) do {        \
        WOLFSSL_ENTER(#id);\
        tls_prof_ccounts[id] = tls_ccount();          \
    } while(0)

#define TLS_PROBE_END(id)   do {                          \
        WOLFSSL_LEAVE(#id,0);\
        uint32_t tmp_##id=tls_ccount();\
        tls_prof_cyc[id] += (uint32_t)(tmp_##id - tls_prof_ccounts[id]); \
        tls_prof_cnt[id]++;                               \
    } while (0)

#else

#define TLS_PROBE_RESET(id) do {} while (0)
#define TLS_PROBE_END(id)   do {} while (0)

#endif

#endif //_TLS_PROBE_H_
