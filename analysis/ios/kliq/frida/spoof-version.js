// Runtime spoof: make Kliq report Store-like version without touching Info.plist seal.
// frida -H 192.168.31.167 -f tr.com.bpn.kliq -l spoof_version.js -q -t inf

var SPOOF_SHORT = '1.30.0';
var SPOOF_BUILD = '1'; // real Store CFBundleVersion for 1.30.0 (from ipatool Kliq.ipa)

function spoofKey(key) {
  if (key === 'CFBundleShortVersionString') return SPOOF_SHORT;
  if (key === 'CFBundleVersion') return SPOOF_BUILD;
  return null;
}

if (!ObjC.available) {
  console.log('[-] ObjC not available');
} else {
  var NSBundle = ObjC.classes.NSBundle;

  Interceptor.attach(NSBundle['- objectForInfoDictionaryKey:'].implementation, {
    onEnter: function (args) {
      this.key = ObjC.Object(args[2]).toString();
    },
    onLeave: function (retval) {
      var v = spoofKey(this.key);
      if (v !== null) {
        retval.replace(ObjC.classes.NSString.stringWithString_(v));
      }
    }
  });

  Interceptor.attach(NSBundle['- infoDictionary'].implementation, {
    onLeave: function (retval) {
      try {
        var dict = ObjC.Object(retval).mutableCopy();
        dict.setObject_forKey_(SPOOF_SHORT, 'CFBundleShortVersionString');
        dict.setObject_forKey_(SPOOF_BUILD, 'CFBundleVersion');
        retval.replace(dict);
      } catch (e) {}
    }
  });

  try {
    var cf = null;
    if (typeof Module.findExportByName === 'function') {
      cf = Module.findExportByName(null, 'CFBundleGetValueForInfoDictionaryKey');
    } else if (typeof Module.getGlobalExportByName === 'function') {
      cf = Module.getGlobalExportByName('CFBundleGetValueForInfoDictionaryKey');
    }
    if (cf) {
      Interceptor.attach(cf, {
        onEnter: function (args) {
          this.key = args[1];
        },
        onLeave: function (retval) {
          try {
            var key = new ObjC.Object(this.key).toString();
            var v = spoofKey(key);
            if (v !== null) {
              retval.replace(ObjC.classes.NSString.stringWithString_(v));
            }
          } catch (e) {}
        }
      });
      console.log('[+] CFBundleGetValueForInfoDictionaryKey hooked');
    } else {
      console.log('[*] CFBundle export not found (NSBundle hooks only)');
    }
  } catch (e) {
    console.log('[*] CF hook skipped: ' + e);
  }

  console.log('[+] Kliq version spoof active → ' + SPOOF_SHORT + ' (' + SPOOF_BUILD + ')');
}
