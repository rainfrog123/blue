/**
 * Frida NSS SSL Bypass - Fixed Version
 */

function log(msg) {
    console.log('[NSS-Bypass] ' + msg);
}

log('Initializing NSS SSL bypass (fixed)...');

// Find NSS module
var nssBase = null;
Process.enumerateModules().forEach(function(mod) {
    if (mod.name === 'libnss3.so') {
        nssBase = mod.base;
        log('Found libnss3.so at ' + mod.base);
    }
});

if (nssBase) {
    // Hook CERT_VerifyCertificate - offset 0x2e960
    try {
        var certVerify = nssBase.add(0x2e960);
        Interceptor.attach(certVerify, {
            onEnter: function(args) {
                log('CERT_VerifyCertificate called');
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    log('CERT_VerifyCertificate returning ' + retval + ' -> forcing to 0 (SECSuccess)');
                    retval.replace(ptr(0));
                }
            }
        });
        log('Hooked CERT_VerifyCertificate');
    } catch (e) {
        log('Failed to hook CERT_VerifyCertificate: ' + e);
    }

    // Hook CERT_VerifyCertificateNow - offset 0x2ef60
    try {
        var certVerifyNow = nssBase.add(0x2ef60);
        Interceptor.attach(certVerifyNow, {
            onEnter: function(args) {
                log('CERT_VerifyCertificateNow called');
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    log('CERT_VerifyCertificateNow returning ' + retval + ' -> forcing to 0');
                    retval.replace(ptr(0));
                }
            }
        });
        log('Hooked CERT_VerifyCertificateNow');
    } catch (e) {
        log('Failed to hook CERT_VerifyCertificateNow: ' + e);
    }

    // Hook CERT_VerifyCert - offset 0x2d360
    try {
        var certVerifyCert = nssBase.add(0x2d360);
        Interceptor.attach(certVerifyCert, {
            onEnter: function(args) {
                log('CERT_VerifyCert called');
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    log('CERT_VerifyCert returning ' + retval + ' -> forcing to 0');
                    retval.replace(ptr(0));
                }
            }
        });
        log('Hooked CERT_VerifyCert');
    } catch (e) {
        log('Failed to hook CERT_VerifyCert: ' + e);
    }

    // Hook CERT_VerifyCertName - offset 0x70e80
    try {
        var certVerifyName = nssBase.add(0x70e80);
        Interceptor.attach(certVerifyName, {
            onEnter: function(args) {
                log('CERT_VerifyCertName called');
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    log('CERT_VerifyCertName returning ' + retval + ' -> forcing to 0');
                    retval.replace(ptr(0));
                }
            }
        });
        log('Hooked CERT_VerifyCertName');
    } catch (e) {
        log('Failed to hook CERT_VerifyCertName: ' + e);
    }
}

// Also hook OpenSSL/libcrypto if available
Process.enumerateModules().forEach(function(mod) {
    if (mod.name === 'libcrypto.so.3') {
        log('Found libcrypto.so.3 at ' + mod.base);
        
        // Hook X509_verify_cert - offset 0x2396e0
        try {
            var x509Verify = mod.base.add(0x2396e0);
            Interceptor.attach(x509Verify, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 1) {
                        log('X509_verify_cert returning ' + retval + ' -> forcing to 1 (success)');
                        retval.replace(ptr(1));
                    }
                }
            });
            log('Hooked X509_verify_cert');
        } catch (e) {
            log('Failed to hook X509_verify_cert: ' + e);
        }
    }
    
    if (mod.name === 'libssl.so.3') {
        log('Found libssl.so.3 at ' + mod.base);
        
        // Hook SSL_get_verify_result - offset 0x34840
        try {
            var sslVerifyResult = mod.base.add(0x34840);
            Interceptor.attach(sslVerifyResult, {
                onLeave: function(retval) {
                    if (!retval.equals(ptr(0))) {
                        log('SSL_get_verify_result returning ' + retval + ' -> forcing to 0 (X509_V_OK)');
                        retval.replace(ptr(0));
                    }
                }
            });
            log('Hooked SSL_get_verify_result');
        } catch (e) {
            log('Failed to hook SSL_get_verify_result: ' + e);
        }
    }
});

log('NSS SSL bypass hooks installed - waiting for SSL connections...');
