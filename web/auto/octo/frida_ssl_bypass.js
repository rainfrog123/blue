/**
 * Frida SSL Pinning Bypass Script for OctoBrowser
 * Hooks OpenSSL and other SSL verification functions
 */

// Color codes for logging
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m'
};

function log(msg, color = colors.green) {
    console.log(`${color}[SSL-Bypass]${colors.reset} ${msg}`);
}

log('Initializing SSL bypass hooks...', colors.cyan);

// ============================================
// OpenSSL Hooks
// ============================================

// Hook SSL_CTX_set_verify - disable certificate verification
try {
    const SSL_CTX_set_verify = Module.findExportByName(null, 'SSL_CTX_set_verify');
    if (SSL_CTX_set_verify) {
        Interceptor.attach(SSL_CTX_set_verify, {
            onEnter: function(args) {
                log(`SSL_CTX_set_verify called, mode: ${args[1]} -> forcing to 0 (SSL_VERIFY_NONE)`);
                args[1] = ptr(0); // SSL_VERIFY_NONE
            }
        });
        log('Hooked SSL_CTX_set_verify');
    }
} catch (e) {
    log(`Failed to hook SSL_CTX_set_verify: ${e}`, colors.yellow);
}

// Hook SSL_set_verify
try {
    const SSL_set_verify = Module.findExportByName(null, 'SSL_set_verify');
    if (SSL_set_verify) {
        Interceptor.attach(SSL_set_verify, {
            onEnter: function(args) {
                log(`SSL_set_verify called, mode: ${args[1]} -> forcing to 0`);
                args[1] = ptr(0);
            }
        });
        log('Hooked SSL_set_verify');
    }
} catch (e) {
    log(`Failed to hook SSL_set_verify: ${e}`, colors.yellow);
}

// Hook SSL_get_verify_result - always return success
try {
    const SSL_get_verify_result = Module.findExportByName(null, 'SSL_get_verify_result');
    if (SSL_get_verify_result) {
        Interceptor.attach(SSL_get_verify_result, {
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    log(`SSL_get_verify_result returned ${retval} -> forcing to 0 (X509_V_OK)`);
                    retval.replace(ptr(0)); // X509_V_OK
                }
            }
        });
        log('Hooked SSL_get_verify_result');
    }
} catch (e) {
    log(`Failed to hook SSL_get_verify_result: ${e}`, colors.yellow);
}

// Hook X509_verify_cert - always return success
try {
    const X509_verify_cert = Module.findExportByName(null, 'X509_verify_cert');
    if (X509_verify_cert) {
        Interceptor.attach(X509_verify_cert, {
            onLeave: function(retval) {
                if (retval.toInt32() !== 1) {
                    log(`X509_verify_cert returned ${retval} -> forcing to 1 (success)`);
                    retval.replace(ptr(1));
                }
            }
        });
        log('Hooked X509_verify_cert');
    }
} catch (e) {
    log(`Failed to hook X509_verify_cert: ${e}`, colors.yellow);
}

// ============================================
// BoringSSL Hooks (Chrome/Chromium uses BoringSSL)
// ============================================

// Hook SSL_CTX_set_custom_verify (BoringSSL)
try {
    const SSL_CTX_set_custom_verify = Module.findExportByName(null, 'SSL_CTX_set_custom_verify');
    if (SSL_CTX_set_custom_verify) {
        Interceptor.attach(SSL_CTX_set_custom_verify, {
            onEnter: function(args) {
                log('SSL_CTX_set_custom_verify called -> replacing callback with bypass');
                // Replace the callback with one that always succeeds
                args[2] = new NativeCallback(function(ssl, out_alert) {
                    return 0; // ssl_verify_ok
                }, 'int', ['pointer', 'pointer']);
            }
        });
        log('Hooked SSL_CTX_set_custom_verify');
    }
} catch (e) {
    log(`SSL_CTX_set_custom_verify not found (expected if not BoringSSL)`, colors.yellow);
}

// ============================================
// Python SSL Hooks (for PyQt apps)
// ============================================

// Try to find Python SSL module functions
try {
    const modules = Process.enumerateModules();
    modules.forEach(function(mod) {
        if (mod.name.includes('ssl') || mod.name.includes('SSL') || mod.name.includes('crypto')) {
            log(`Found SSL-related module: ${mod.name} at ${mod.base}`, colors.blue);
        }
    });
} catch (e) {
    log(`Error enumerating modules: ${e}`, colors.yellow);
}

// ============================================
// Qt SSL Hooks
// ============================================

// Hook QSslSocket::setPeerVerifyMode
try {
    // Find Qt SSL symbols
    const qtSymbols = [
        '_ZN10QSslSocket18setPeerVerifyModeENS_14PeerVerifyModeE',
        '_ZN10QSslSocket14setVerifyModeENS_10VerifyModeE'
    ];
    
    qtSymbols.forEach(function(sym) {
        const addr = Module.findExportByName(null, sym);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    log(`Qt SSL verify mode called -> forcing to VerifyNone`);
                    args[1] = ptr(0); // QSslSocket::VerifyNone
                }
            });
            log(`Hooked Qt symbol: ${sym}`);
        }
    });
} catch (e) {
    log(`Qt SSL hooks: ${e}`, colors.yellow);
}

// ============================================
// Generic Certificate Verification Bypass
// ============================================

// Hook common verification function names
const verifyFunctions = [
    'SSL_CTX_set_cert_verify_callback',
    'X509_STORE_CTX_set_verify_cb',
    'SSL_set_verify_result'
];

verifyFunctions.forEach(function(funcName) {
    try {
        const func = Module.findExportByName(null, funcName);
        if (func) {
            Interceptor.attach(func, {
                onEnter: function(args) {
                    log(`${funcName} called`);
                },
                onLeave: function(retval) {
                    log(`${funcName} returned: ${retval}`);
                }
            });
            log(`Hooked ${funcName}`);
        }
    } catch (e) {}
});

// ============================================
// Monitor SSL Connections
// ============================================

// Hook SSL_connect to log connections
try {
    const SSL_connect = Module.findExportByName(null, 'SSL_connect');
    if (SSL_connect) {
        Interceptor.attach(SSL_connect, {
            onEnter: function(args) {
                this.ssl = args[0];
            },
            onLeave: function(retval) {
                const result = retval.toInt32();
                if (result === 1) {
                    log(`SSL_connect succeeded`, colors.green);
                } else {
                    log(`SSL_connect failed with ${result}`, colors.red);
                }
            }
        });
        log('Hooked SSL_connect for monitoring');
    }
} catch (e) {}

// Hook SSL_read/SSL_write to log data transfer
try {
    const SSL_write = Module.findExportByName(null, 'SSL_write');
    if (SSL_write) {
        Interceptor.attach(SSL_write, {
            onEnter: function(args) {
                const len = args[2].toInt32();
                if (len > 0 && len < 10000) {
                    try {
                        const data = args[1].readUtf8String(Math.min(len, 200));
                        if (data && data.length > 0) {
                            log(`SSL_write (${len} bytes): ${data.substring(0, 100)}...`, colors.cyan);
                        }
                    } catch (e) {}
                }
            }
        });
        log('Hooked SSL_write for traffic monitoring');
    }
} catch (e) {}

log('SSL bypass hooks initialized!', colors.green);
log('Waiting for SSL connections...', colors.cyan);
