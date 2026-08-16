// Capture OTP/SMS related HTTP + JSON. Keep version spoof.
// frida -H 192.168.31.167 -f tr.com.bpn.kliq -l spoof_and_capture_otp.js -q -t inf

var SPOOF_SHORT = '1.30.0';
var SPOOF_BUILD = '1'; // real Store CFBundleVersion for 1.30.0

function spoofKey(key) {
  if (key === 'CFBundleShortVersionString') return SPOOF_SHORT;
  if (key === 'CFBundleVersion') return SPOOF_BUILD;
  return null;
}

function interestingUrl(u) {
  return /otp|sms|smsotp|verify|login|register|auth|phone|msisdn|customer|individual|token|bpn|kliq/i.test(u);
}

function interestingBody(t) {
  return /otp|sms|minute|recently|phone|msisdn|device|deviceId|device_id|fingerprint|cooldown|rate|warning|error|secret/i.test(t);
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
  console.log('[+] spoof ' + SPOOF_SHORT);

  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
    onEnter: function (args) { this.data = ObjC.Object(args[2]); },
    onLeave: function (retval) {
      try {
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(this.data, 4);
        if (!s) return;
        var t = s.toString();
        if (interestingBody(t)) console.log('[JSON] ' + t.slice(0, 5000));
      } catch (e) {}
    }
  });

  // also serialize requests
  try {
    Interceptor.attach(ObjC.classes.NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation, {
      onLeave: function (retval) {
        try {
          var data = ObjC.Object(retval);
          if (!data || data.isNull()) return;
          var s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
          if (!s) return;
          var t = s.toString();
          if (interestingBody(t)) console.log('[REQJSON] ' + t.slice(0, 3000));
        } catch (e) {}
      }
    });
  } catch (e) {}

  Interceptor.attach(ObjC.classes.NSURLSessionTask['- resume'].implementation, {
    onEnter: function (args) {
      try {
        var task = ObjC.Object(args[0]);
        var req = task.currentRequest() || task.originalRequest();
        if (!req) return;
        var u = req.URL().absoluteString().toString();
        if (!interestingUrl(u) && !interestingBody(u)) return;
        console.log('[REQ] ' + req.HTTPMethod().toString() + ' ' + u);
        try {
          var headers = req.allHTTPHeaderFields();
          if (headers) console.log('[HDR] ' + headers.toString().slice(0, 1500));
        } catch (e) {}
        try {
          var body = req.HTTPBody();
          if (body && body.length() > 0) {
            var s = ObjC.classes.NSString.alloc().initWithData_encoding_(body, 4);
            if (s) console.log('[BODY] ' + s.toString().slice(0, 3000));
          }
        } catch (e) {}
      } catch (e) {}
    }
  });
  console.log('[+] OTP capture ready — trigger Send SMS once');
}
