/**
 * Frida SSL Pinning Bypass v2 - For PyInstaller/AppImage apps
 * Waits for SSL libraries to load, then hooks them
 */

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

log('SSL Bypass v2 - Waiting for libraries to load...', colors.cyan);

// Track hooked libraries
var hookedLibs = new Set();

function hookSSLFunctions(moduleName) {
    if (hookedLibs.has(moduleName)) return;
    
    try {
        const mod = Process.getModuleByName(moduleName);
        if (!mod) return;
        
        hookedLibs.add(moduleName);
        log(`Found SSL library: ${moduleName} at ${mod.base}`, colors.blue);
        
        // Hook SSL_CTX_set_verify
        const SSL_CTX_set_verify = mod.findExportByName('SSL_CTX_set_verify');
        if (SSL_CTX_set_verify) {
            Interceptor.attach(SSL_CTX_set_verify, {
                onEnter: function(args) {
                    log(`${moduleName}: SSL_CTX_set_verify mode=${args[1]} -> 0`);
                    args[1] = ptr(0);
                }
            });
            log(`Hooked SSL_CTX_set_verify in ${moduleName}`, colors.green);
        }
        
        // Hook SSL_set_verify
        const SSL_set_verify = mod.findExportByName('SSL_set_verify');
        if (SSL_set_verify) {
            Interceptor.attach(SSL_set_verify, {
                onEnter: function(args) {
                    args[1] = ptr(0);
                }
            });
            log(`Hooked SSL_set_verify in ${moduleName}`, colors.green);
        }
        
        // Hook SSL_get_verify_result
        const SSL_get_verify_result = mod.findExportByName('SSL_get_verify_result');
        if (SSL_get_verify_result) {
            Interceptor.attach(SSL_get_verify_result, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        log(`SSL_get_verify_result: ${retval} -> 0`);
                        retval.replace(ptr(0));
                    }
                }
            });
            log(`Hooked SSL_get_verify_result in ${moduleName}`, colors.green);
        }
        
        // Hook X509_verify_cert
        const X509_verify_cert = mod.findExportByName('X509_verify_cert');
        if (X509_verify_cert) {
            Interceptor.attach(X509_verify_cert, {
                onLeave: function(retval) {
                    if (retval.toInt32() <= 0) {
                        log(`X509_verify_cert: ${retval} -> 1`);
                        retval.replace(ptr(1));
                    }
                }
            });
            log(`Hooked X509_verify_cert in ${moduleName}`, colors.green);
        }
        
    } catch (e) {
        // Silently ignore if module not found
    }
}

// List of common SSL library names
const sslLibNames = [
    'libssl.so.3',
    'libssl.so.1.1',
    'libssl.so.1.0.0',
    'libssl.so',
    'libcrypto.so.3',
    'libcrypto.so.1.1',
    'libcrypto.so',
    'ssl.cpython',
    '_ssl.cpython'
];

// Initial scan
log('Scanning loaded modules...', colors.cyan);
Process.enumerateModules().forEach(function(mod) {
    const name = mod.name.toLowerCase();
    if (name.includes('ssl') || name.includes('crypto')) {
        log(`Found: ${mod.name}`, colors.blue);
        hookSSLFunctions(mod.name);
    }
});

// Watch for new modules being loaded
Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter: function(args) {
        this.path = args[0].readCString();
    },
    onLeave: function(retval) {
        if (this.path) {
            const path = this.path.toLowerCase();
            if (path.includes('ssl') || path.includes('crypto')) {
                log(`dlopen: ${this.path}`, colors.yellow);
                // Try to hook after a small delay
                setTimeout(function() {
                    const basename = this.path.split('/').pop();
                    hookSSLFunctions(basename);
                }.bind(this), 100);
            }
        }
    }
});

// Also watch dlopen with versioned libraries
try {
    Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
        onEnter: function(args) {
            if (args[0].isNull()) return;
            const path = args[0].readCString();
            if (path && (path.includes('ssl') || path.includes('crypto'))) {
                log(`Loading: ${path}`, colors.yellow);
            }
        }
    });
} catch(e) {}

// Periodically check for new SSL libraries
setInterval(function() {
    sslLibNames.forEach(function(name) {
        hookSSLFunctions(name);
    });
}, 2000);

log('SSL Bypass v2 initialized - monitoring for SSL libraries', colors.green);
