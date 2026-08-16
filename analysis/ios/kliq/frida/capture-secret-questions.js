// Log HTTP JSON that looks like secret/security questions; optional softer version spoof.
// frida -H 192.168.31.167 -n Kliq -l capture_secret_questions.js -q -t inf

var SPOOF = true;
var SPOOF_SHORT = '1.28.0'; // legacy soft-spoof experiment; prefer spoof_version.js 1.30.0 / 1
var SPOOF_BUILD = '1';

function spoofKey(key) {
  if (key === 'CFBundleShortVersionString') return SPOOF_SHORT;
  if (key === 'CFBundleVersion') return SPOOF_BUILD;
  return null;
}

if (ObjC.available) {
  if (SPOOF) {
    var NSBundle = ObjC.classes.NSBundle;
    Interceptor.attach(NSBundle['- objectForInfoDictionaryKey:'].implementation, {
      onEnter: function (args) { this.key = ObjC.Object(args[2]).toString(); },
      onLeave: function (retval) {
        var v = spoofKey(this.key);
        if (v) retval.replace(ObjC.classes.NSString.stringWithString_(v));
      }
    });
    console.log('[+] soft spoof ' + SPOOF_SHORT);
  }

  function logNSData(data, prefix) {
    try {
      if (!data || data.length() === 0) return;
      var s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
      if (!s) s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 1);
      if (!s) return;
      var t = s.toString();
      if (/question|secret|Security|enqura|Challenge/i.test(t)) {
        console.log(prefix + t.slice(0, 2000));
      }
    } catch (e) {}
  }

  // NSURLSession data tasks
  try {
    var NSURLSession = ObjC.classes.NSURLSession;
    Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
      onEnter: function (args) {
        var req = ObjC.Object(args[2]);
        var url = req.URL().absoluteString().toString();
        var block = new ObjC.Block(args[3]);
        var orig = block.implementation;
        block.implementation = function (data, response, error) {
          try {
            console.log('[HTTP] ' + url);
            logNSData(data, '[BODY] ');
          } catch (e) {}
          return orig(data, response, error);
        };
      }
    });
    console.log('[+] NSURLSession hooked');
  } catch (e) {
    console.log('[-] session hook ' + e);
  }
}
