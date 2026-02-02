/**
 * Frida SSL Pinning Bypass v3 - Fixed for Frida JS runtime
 */

function log(msg) {
    console.log('[SSL-Bypass] ' + msg);
}

log('Initializing SSL bypass...');

// Enumerate all modules to find SSL libraries
log('Enumerating modules...');
var modules = Process.enumerateModules();
modules.forEach(function(mod) {
    var name = mod.name.toLowerCase();
    if (name.indexOf('ssl') !== -1 || name.indexOf('crypto') !== -1 || name.indexOf('nss') !== -1) {
        log('Found: ' + mod.name + ' at ' + mod.base);
    }
});

// Try to hook OpenSSL functions from any loaded library
function tryHook(funcName, module) {
    var addr;
    try {
        if (module) {
            addr = Module.findExportByName(module, funcName);
        } else {
            addr = Module.findExportByName(null, funcName);
        }
        return addr;
    } catch (e) {
        return null;
    }
}

// SSL_CTX_set_verify
var ssl_ctx_set_verify = tryHook('SSL_CTX_set_verify', null);
if (ssl_ctx_set_verify) {
    Interceptor.attach(ssl_ctx_set_verify, {
        onEnter: function(args) {
            log('SSL_CTX_set_verify called, setting verify mode to NONE');
            args[1] = ptr(0);
        }
    });
    log('Hooked SSL_CTX_set_verify at ' + ssl_ctx_set_verify);
}

// SSL_set_verify
var ssl_set_verify = tryHook('SSL_set_verify', null);
if (ssl_set_verify) {
    Interceptor.attach(ssl_set_verify, {
        onEnter: function(args) {
            args[1] = ptr(0);
        }
    });
    log('Hooked SSL_set_verify at ' + ssl_set_verify);
}

// SSL_get_verify_result
var ssl_get_verify = tryHook('SSL_get_verify_result', null);
if (ssl_get_verify) {
    Interceptor.attach(ssl_get_verify, {
        onLeave: function(retval) {
            if (!retval.equals(ptr(0))) {
                log('SSL_get_verify_result was ' + retval + ', returning 0');
                retval.replace(ptr(0));
            }
        }
    });
    log('Hooked SSL_get_verify_result at ' + ssl_get_verify);
}

// X509_verify_cert
var x509_verify = tryHook('X509_verify_cert', null);
if (x509_verify) {
    Interceptor.attach(x509_verify, {
        onLeave: function(retval) {
            if (retval.toInt32() !== 1) {
                log('X509_verify_cert was ' + retval + ', returning 1');
                retval.replace(ptr(1));
            }
        }
    });
    log('Hooked X509_verify_cert at ' + x509_verify);
}

// For BoringSSL (Chromium) - hook SSL_CTX_set_custom_verify
var ssl_custom_verify = tryHook('SSL_CTX_set_custom_verify', null);
if (ssl_custom_verify) {
    log('Found BoringSSL SSL_CTX_set_custom_verify');
}

// Hook dlopen to catch late-loaded SSL libraries
var dlopen = Module.findExportByName(null, 'dlopen');
if (dlopen) {
    Interceptor.attach(dlopen, {
        onEnter: function(args) {
            if (!args[0].isNull()) {
                var path = args[0].readCString();
                if (path && (path.indexOf('ssl') !== -1 || path.indexOf('crypto') !== -1)) {
                    log('dlopen loading: ' + path);
                }
            }
        }
    });
    log('Watching dlopen for SSL libraries');
}

// Monitor SSL_connect for connection attempts
var ssl_connect = tryHook('SSL_connect', null);
if (ssl_connect) {
    Interceptor.attach(ssl_connect, {
        onLeave: function(retval) {
            var result = retval.toInt32();
            if (result === 1) {
                log('SSL_connect succeeded');
            } else if (result <= 0) {
                log('SSL_connect failed: ' + result);
            }
        }
    });
    log('Monitoring SSL_connect');
}

// Try to hook BIO_s_socket for network monitoring
var bio_write = tryHook('BIO_write', null);
if (bio_write) {
    Interceptor.attach(bio_write, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            if (len > 0 && len < 1000) {
                try {
                    var buf = args[1].readUtf8String(Math.min(len, 100));
                    if (buf && buf.length > 4) {
                        log('BIO_write: ' + buf.substring(0, 50));
                    }
                } catch(e) {}
            }
        }
    });
}

log('SSL bypass initialized!');
log('Note: OctoBrowser may use NSS or BoringSSL instead of OpenSSL');
