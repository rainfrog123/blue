// Spawn helper: soft version spoof + capture secret-question JSON
// frida -H 192.168.31.167 -f tr.com.bpn.kliq -l spoof_and_capture.js -q -t inf

var SPOOF_SHORT = '1.28.0'; // legacy; prefer spoof_rotate_device_key.js
var SPOOF_BUILD = '1';

function spoofKey(key) {
  if (key === 'CFBundleShortVersionString') return SPOOF_SHORT;
  if (key === 'CFBundleVersion') return SPOOF_BUILD;
  return null;
}

if (ObjC.available) {
  var NSBundle = ObjC.classes.NSBundle;
  Interceptor.attach(NSBundle['- objectForInfoDictionaryKey:'].implementation, {
    onEnter: function (args) { this.key = ObjC.Object(args[2]).toString(); },
    onLeave: function (retval) {
      var v = spoofKey(this.key);
      if (v) retval.replace(ObjC.classes.NSString.stringWithString_(v));
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
  console.log('[+] spoof ' + SPOOF_SHORT + ' / ' + SPOOF_BUILD);

  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
    onEnter: function (args) { this.data = ObjC.Object(args[2]); },
    onLeave: function (retval) {
      try {
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(this.data, 4);
        if (!s) return;
        var t = s.toString();
        if (/question|secret|Secret|security|Security|challenge|Challenge/i.test(t)) {
          console.log('[JSON] ' + t.slice(0, 4000));
        }
      } catch (e) {}
    }
  });

  Interceptor.attach(ObjC.classes.NSURLSessionTask['- resume'].implementation, {
    onEnter: function (args) {
      try {
        var task = ObjC.Object(args[0]);
        var req = task.currentRequest() || task.originalRequest();
        if (!req) return;
        var u = req.URL().absoluteString().toString();
        if (/bpn|kliq|auth|login|secret|question|security|customer|otp|individual/i.test(u)) {
          console.log('[REQ] ' + req.HTTPMethod().toString() + ' ' + u);
        }
      } catch (e) {}
    }
  });
  console.log('[+] capture hooks ready — redo flow to security questions');
}
