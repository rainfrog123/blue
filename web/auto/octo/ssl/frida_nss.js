/**
 * Frida NSS (Network Security Services) SSL Bypass
 * For applications using libnss3.so (Firefox, Chromium, QtWebEngine)
 */

function log(msg) {
    console.log('[NSS-Bypass] ' + msg);
}

log('Initializing NSS SSL bypass...');

// Find NSS library
var nssModule = null;
var modules = Process.enumerateModules();
modules.forEach(function(mod) {
    if (mod.name === 'libnss3.so') {
        nssModule = mod;
        log('Found libnss3.so at ' + mod.base);
    }
});

if (!nssModule) {
    log('ERROR: libnss3.so not found!');
} else {
    // Hook NSS SSL functions
    
    // SSL_AuthCertificateHook - set custom certificate verification callback
    var SSL_AuthCertificateHook = Module.findExportByName('libnss3.so', 'SSL_AuthCertificateHook');
    if (SSL_AuthCertificateHook) {
        Interceptor.attach(SSL_AuthCertificateHook, {
            onEnter: function(args) {
                log('SSL_AuthCertificateHook called - replacing callback');
                // Replace callback with one that always returns SECSuccess (0)
                var bypassCallback = new NativeCallback(function(arg, fd, checkSig, isServer) {
                    log('Certificate verification bypassed!');
                    return 0; // SECSuccess
                }, 'int', ['pointer', 'pointer', 'int', 'int']);
                args[1] = bypassCallback;
            }
        });
        log('Hooked SSL_AuthCertificateHook');
    }
    
    // SSL_BadCertHook - bad certificate callback
    var SSL_BadCertHook = Module.findExportByName('libnss3.so', 'SSL_BadCertHook');
    if (SSL_BadCertHook) {
        Interceptor.attach(SSL_BadCertHook, {
            onEnter: function(args) {
                log('SSL_BadCertHook called - replacing callback');
                var bypassCallback = new NativeCallback(function(arg, fd) {
                    log('Bad certificate callback - returning SECSuccess');
                    return 0; // SECSuccess
                }, 'int', ['pointer', 'pointer']);
                args[1] = bypassCallback;
            }
        });
        log('Hooked SSL_BadCertHook');
    }
    
    // CERT_VerifyCertificate - direct cert verification
    var CERT_VerifyCertificate = Module.findExportByName('libnss3.so', 'CERT_VerifyCertificate');
    if (CERT_VerifyCertificate) {
        Interceptor.attach(CERT_VerifyCertificate, {
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    log('CERT_VerifyCertificate returned ' + retval + ' -> forcing to 0 (SECSuccess)');
                    retval.replace(ptr(0));
                }
            }
        });
        log('Hooked CERT_VerifyCertificate');
    }
    
    // CERT_VerifyCertificateName - verify certificate hostname
    var CERT_VerifyCertificateName = Module.findExportByName('libnss3.so', 'CERT_VerifyCertificateName');
    if (CERT_VerifyCertificateName) {
        Interceptor.attach(CERT_VerifyCertificateName, {
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    log('CERT_VerifyCertificateName returning success');
                    retval.replace(ptr(0));
                }
            }
        });
        log('Hooked CERT_VerifyCertificateName');
    }
    
    // SSL_SetPKCS11PinArg
    var SSL_ForceHandshake = Module.findExportByName('libnss3.so', 'SSL_ForceHandshake');
    if (SSL_ForceHandshake) {
        Interceptor.attach(SSL_ForceHandshake, {
            onLeave: function(retval) {
                var result = retval.toInt32();
                if (result < 0) {
                    log('SSL_ForceHandshake failed: ' + result);
                } else {
                    log('SSL_ForceHandshake succeeded');
                }
            }
        });
        log('Monitoring SSL_ForceHandshake');
    }
}

// Also try to hook common Chromium/BoringSSL cert verification
// Chromium uses its own certificate verifier

// Try to find and hook CertVerifyProc
var certVerifySymbols = [
    '_ZN3net13CertVerifyProc6VerifyEPNS_15X509CertificateERKSsRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEiPKNS_10CRLSetBaseEPNS_19CertVerifyResultDataE',
    '_ZN3net16CertVerifyProcNSS13VerifyInternalEPNS_15X509CertificateERKSsi'
];

certVerifySymbols.forEach(function(sym) {
    var addr = Module.findExportByName(null, sym);
    if (addr) {
        log('Found Chromium cert verify: ' + sym);
    }
});

// Monitor PR_Read/PR_Write for NSPR layer
var PR_Read = Module.findExportByName('libnspr4.so', 'PR_Read');
if (PR_Read) {
    log('Found NSPR PR_Read - can monitor encrypted traffic');
}

var PR_Write = Module.findExportByName('libnspr4.so', 'PR_Write');
if (PR_Write) {
    log('Found NSPR PR_Write - can monitor encrypted traffic');
}

// Hook SSL_GetChannelInfo for debugging
var SSL_GetChannelInfo = Module.findExportByName('libnss3.so', 'SSL_GetChannelInfo');
if (SSL_GetChannelInfo) {
    Interceptor.attach(SSL_GetChannelInfo, {
        onLeave: function(retval) {
            if (retval.toInt32() === 0) {
                log('SSL channel established');
            }
        }
    });
}

log('NSS SSL bypass hooks initialized!');
log('Waiting for SSL connections...');
