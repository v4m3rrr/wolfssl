#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/tls_probe.h>

#ifdef TLS_PROBE_ENABLE

ProbeBucket tls_p_buckets[TLS_P_BUCKET_SIZE] = {0};

const char *tls_p_bucket_name(enum TLS_P_BUCKET type)
{
	switch (type) {
	case TLS_P_BUCKET_KEX:
		return "KEX";
	case TLS_P_BUCKET_AUTH_SRV_CHAIN:
		return "AUTH-SRV-CHAIN";
	case TLS_P_BUCKET_PEER_KEY:
		return "PEER-KEY";
	case TLS_P_BUCKET_AUTH_SRV_CORE:
		return "AUTH-SRV-CORE";
	case TLS_P_BUCKET_AUTH_CLI_CORE:
		return "AUTH-CLI-CORE";
	case TLS_P_BUCKET_KEY_DECODE:
		return "KEY-DECODE";
	case TLS_P_BUCKET_VERIFY_KEY:
		return "VERIFY-KEY";
	case TLS_P_BUCKET_KEYSCHED_HS:
		return "KEYSCHED-HS";
	case TLS_P_BUCKET_KEYSCHED_AHS:
		return "KEYSCHED-AHS";
	case TLS_P_BUCKET_KEYSCHED_MS:
		return "KEYSCHED-MS";
	case TLS_P_BUCKET_FINISHED:
		return "FINISHED";
	case TLS_P_BUCKET_TRANSCRIPT:
		return "TRANSCRIPT";
	case TLS_P_BUCKET_AEAD:
		return "AEAD";
	case TLS_P_BUCKET_NET_WAIT:
		return "NET-WAIT";
	case TLS_P_BUCKET_HS_TOTAL:
		return "HANDSHAKE-TOTAL";
	case TLS_P_BUCKET_SIZE:
	default:
		return "invalid";
	}
}


uint32_t tls_p_ccount(void)
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
#endif // TLS_PROBE_ENABLE
