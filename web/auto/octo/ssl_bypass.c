/*
 * SSL Certificate Verification Bypass via LD_PRELOAD
 * Compile: gcc -shared -fPIC -o ssl_bypass.so ssl_bypass.c -ldl
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

// OpenSSL functions
typedef int (*SSL_CTX_set_verify_t)(void *ctx, int mode, void *callback);
typedef int (*SSL_set_verify_t)(void *ssl, int mode, void *callback);
typedef long (*SSL_get_verify_result_t)(void *ssl);
typedef int (*X509_verify_cert_t)(void *ctx);

// NSS functions  
typedef int (*CERT_VerifyCertificate_t)(void *a, void *b, int c, int d, long e, void *f, void *g, void *h);

static int initialized = 0;

static void init_log(void) {
    if (!initialized) {
        fprintf(stderr, "[SSL_BYPASS] Loaded - certificate verification will be bypassed\n");
        initialized = 1;
    }
}

// Bypass SSL_CTX_set_verify
int SSL_CTX_set_verify(void *ctx, int mode, void *callback) {
    init_log();
    fprintf(stderr, "[SSL_BYPASS] SSL_CTX_set_verify called, mode=%d -> forcing to 0\n", mode);
    
    SSL_CTX_set_verify_t real_func = dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
    if (real_func) {
        return real_func(ctx, 0, NULL);  // SSL_VERIFY_NONE = 0
    }
    return 0;
}

// Bypass SSL_set_verify  
int SSL_set_verify(void *ssl, int mode, void *callback) {
    init_log();
    fprintf(stderr, "[SSL_BYPASS] SSL_set_verify called, mode=%d -> forcing to 0\n", mode);
    
    SSL_set_verify_t real_func = dlsym(RTLD_NEXT, "SSL_set_verify");
    if (real_func) {
        return real_func(ssl, 0, NULL);
    }
    return 0;
}

// Bypass SSL_get_verify_result
long SSL_get_verify_result(void *ssl) {
    init_log();
    fprintf(stderr, "[SSL_BYPASS] SSL_get_verify_result called -> returning 0 (X509_V_OK)\n");
    return 0;  // X509_V_OK
}

// Bypass X509_verify_cert
int X509_verify_cert(void *ctx) {
    init_log();
    fprintf(stderr, "[SSL_BYPASS] X509_verify_cert called -> returning 1 (success)\n");
    return 1;
}

// Bypass CERT_VerifyCertificate (NSS)
int CERT_VerifyCertificate(void *a, void *b, int c, int d, long e, void *f, void *g, void *h) {
    init_log();
    fprintf(stderr, "[SSL_BYPASS] CERT_VerifyCertificate (NSS) called -> returning 0 (SECSuccess)\n");
    return 0;  // SECSuccess
}

// Bypass CERT_VerifyCertificateName (NSS)
int CERT_VerifyCertificateName(void *cert, const char *hostname) {
    init_log();
    fprintf(stderr, "[SSL_BYPASS] CERT_VerifyCertificateName (NSS) called for %s -> returning 0\n", 
            hostname ? hostname : "NULL");
    return 0;  // SECSuccess
}
