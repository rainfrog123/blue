// Spoof version + rotate device_key in JSON bodies (bypass server SMS throttle keyed by device)
// frida -H 192.168.31.167 -f tr.com.bpn.kliq -l spoof_rotate_device_key.js -q -t inf

var SPOOF_SHORT = '1.30.0';
var SPOOF_BUILD = '1'; // real Store CFBundleVersion for 1.30.0 (from ipatool Kliq.ipa)

function uuidv4() {
  // RFC-ish UUID via Math.random (good enough for device_key rotation)
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    var r = (Math.random() * 16) | 0;
    var v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16).toUpperCase();
  });
}

var NEW_DEVICE_KEY = uuidv4();
console.log('[+] new device_key = ' + NEW_DEVICE_KEY);

function spoofKey(key) {
  if (key === 'CFBundleShortVersionString') return SPOOF_SHORT;
  if (key === 'CFBundleVersion') return SPOOF_BUILD;
  return null;
}

function patchDeviceKeyInJsonText(t) {
  if (!t || t.indexOf('device_key') < 0) return null;
  // replace any UUID-looking device_key value
  var patched = t.replace(
    /("device_key"\s*:\s*")([0-9A-Fa-f-]{36})(")/g,
    '$1' + NEW_DEVICE_KEY + '$3'
  );
  if (patched === t) return null;
  return patched;
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

  // Patch outbound JSON bodies produced by NSJSONSerialization
  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation, {
    onLeave: function (retval) {
      try {
        var data = ObjC.Object(retval);
        if (!data || data.isNull() || data.length() === 0) return;
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
        if (!s) return;
        var t = s.toString();
        var patched = patchDeviceKeyInJsonText(t);
        if (!patched) return;
        console.log('[*] patched device_key in JSON body');
        var nd = ObjC.classes.NSString.stringWithString_(patched).dataUsingEncoding_(4);
        retval.replace(nd);
      } catch (e) {
        console.log('patch err ' + e);
      }
    }
  });

  // Also patch HTTPBody on resume if already set as raw JSON string/data
  Interceptor.attach(ObjC.classes.NSURLSessionTask['- resume'].implementation, {
    onEnter: function (args) {
      try {
        var task = ObjC.Object(args[0]);
        var req = task.currentRequest() || task.originalRequest();
        if (!req) return;
        var u = req.URL().absoluteString().toString();
        var body = req.HTTPBody();
        if (body && body.length() > 0) {
          var s = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);
          if (s) {
            var t = s.toString();
            var patched = patchDeviceKeyInJsonText(t);
            if (patched) {
              var mutable = req.mutableCopy();
              mutable.setHTTPBody_(ObjC.classes.NSString.stringWithString_(patched).dataUsingEncoding_(4));
              // NSURLSessionTask request may be immutable copy already in flight — best-effort
              console.log('[REQ] ' + req.HTTPMethod().toString() + ' ' + u);
              console.log('[BODY-patched?] ' + patched.slice(0, 500));
            } else if (/otp|sms|phone|initialize|login|register|auth/i.test(u) || /device_key|phone/i.test(t)) {
              console.log('[REQ] ' + req.HTTPMethod().toString() + ' ' + u);
              console.log('[BODY] ' + t.slice(0, 1500));
            }
          }
        } else if (/otp|sms|phone|initialize|login|register/i.test(u)) {
          console.log('[REQ] ' + req.HTTPMethod().toString() + ' ' + u + ' (no body)');
        }
      } catch (e) {}
    }
  });

  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
    onEnter: function (args) { this.data = ObjC.Object(args[2]); },
    onLeave: function (retval) {
      try {
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(this.data, 4);
        if (!s) return;
        var t = s.toString();
        if (/otp|sms|minute|recently|device_key|phone|error|warning/i.test(t)) {
          console.log('[JSON] ' + t.slice(0, 4000));
        }
      } catch (e) {}
    }
  });

  console.log('[+] spoof + device_key rotation ready');
}
