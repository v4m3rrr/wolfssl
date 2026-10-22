#ifndef _TLS_PROBE_H_
#define _TLS_PROBE_H_

#ifdef TLS_PROBE_ENABLE
#include <stdint.h>

enum TLS_P_BUCKET{
    TLS_P_BUCKET_KEX,
    TLS_P_BUCKET_AUTH_SRV_CHAIN,
    TLS_P_BUCKET_PEER_KEY,
    TLS_P_BUCKET_AUTH_SRV_CORE,
    TLS_P_BUCKET_AUTH_CLI_CORE,
    TLS_P_BUCKET_KEY_DECODE,
    TLS_P_BUCKET_VERIFY_KEY,
    TLS_P_BUCKET_KEYSCHED_HS,
    TLS_P_BUCKET_KEYSCHED_AHS,
    TLS_P_BUCKET_KEYSCHED_MS,
    TLS_P_BUCKET_FINISHED,
    TLS_P_BUCKET_TRANSCRIPT,
    TLS_P_BUCKET_AEAD,
    TLS_P_BUCKET_NET_WAIT,
    TLS_P_BUCKET_HS_TOTAL,
    TLS_P_BUCKET_SIZE,
};

typedef struct {
    uint32_t repeats;
    uint32_t start;
    uint64_t cycles;
    uint8_t is_running;
    uint8_t start_calls;
    uint8_t pause_calls;
} ProbeBucket;

uint32_t tls_p_ccount(void);
const char *tls_p_bucket_name(enum TLS_P_BUCKET type);
extern ProbeBucket tls_p_buckets[TLS_P_BUCKET_SIZE];

#define BUCKET_KEX \
    (&tls_p_buckets[TLS_P_BUCKET_KEX])
#define BUCKET_AUTH_SRV_CHAIN \
    (&tls_p_buckets[TLS_P_BUCKET_AUTH_SRV_CHAIN])
#define BUCKET_PEER_KEY \
    (&tls_p_buckets[TLS_P_BUCKET_PEER_KEY])
#define BUCKET_AUTH_SRV_CORE \
    (&tls_p_buckets[TLS_P_BUCKET_AUTH_SRV_CORE])
#define BUCKET_AUTH_CLI_CORE \
    (&tls_p_buckets[TLS_P_BUCKET_AUTH_CLI_CORE])
#define BUCKET_KEY_DECODE \
    (&tls_p_buckets[TLS_P_BUCKET_KEY_DECODE])
#define BUCKET_VERIFY_KEY \
    (&tls_p_buckets[TLS_P_BUCKET_VERIFY_KEY])
#define BUCKET_KEYSCHED_HS \
    (&tls_p_buckets[TLS_P_BUCKET_KEYSCHED_HS])
#define BUCKET_KEYSCHED_AHS \
    (&tls_p_buckets[TLS_P_BUCKET_KEYSCHED_AHS])
#define BUCKET_KEYSCHED_MS \
    (&tls_p_buckets[TLS_P_BUCKET_KEYSCHED_MS])
#define BUCKET_FINISHED \
    (&tls_p_buckets[TLS_P_BUCKET_FINISHED])
#define BUCKET_TRANSCRIPT \
    (&tls_p_buckets[TLS_P_BUCKET_TRANSCRIPT])
#define BUCKET_AEAD \
    (&tls_p_buckets[TLS_P_BUCKET_AEAD])
#define BUCKET_NET_WAIT \
    (&tls_p_buckets[TLS_P_BUCKET_NET_WAIT])
#define BUCKET_HS_TOTAL \
    (&tls_p_buckets[TLS_P_BUCKET_HS_TOTAL])

#define TLS_PROBE_RESET() do {                                              \
    for(int i=0;i<TLS_P_BUCKET_SIZE;i++){                                   \
        if (tls_p_buckets[i].start_calls != tls_p_buckets[i].pause_calls)   \
            abort();                                                        \
        tls_p_buckets[i].cycles = 0;                                         \
    }                                                                       \
} while(0)

#define TLS_PROBE_START(bucket) do {                                        \
    if ((bucket)->is_running)                                               \
        abort();                                                            \
    (bucket)->start_calls++;                                                \
    (bucket)->start = tls_p_ccount();                                       \
    (bucket)->is_running = 1;                                               \
} while(0)

#define TLS_PROBE_PAUSE(bucket) do {                                        \
    if (!(bucket)->is_running)                                              \
        abort();                                                            \
    (bucket)->cycles += tls_p_ccount() - (bucket)->start;                   \
    (bucket)->is_running = 0;                                               \
    (bucket)->pause_calls++;                                                \
} while(0)

#define TLS_PROBE_COUNT() do {                                              \
    for(int i=0;i<TLS_P_BUCKET_SIZE;i++){                                   \
        if (tls_p_buckets[i].start_calls != tls_p_buckets[i].pause_calls)   \
            abort();                                                        \
        tls_p_buckets[i].repeats++;                                         \
    }                                                                       \
} while(0)

#else

#define TLS_PROBE_START(id) do { } while(0)
#define TLS_PROBE_PAUSE(id) do { } while(0)
#define TLS_PROBE_COUNT() do { } while(0)

#endif // TLS_PROBE_ENABLE

#endif // _TLS_PROBE_H_
