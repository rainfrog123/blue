// Full traffic capture + version spoof + device_key rotate
// frida -H 192.168.31.167 -f tr.com.bpn.kliq -l spoof_rotate_capture_all.js -q -t inf

var SPOOF_SHORT = '1.30.0';
var SPOOF_BUILD = '1';

function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    var r = (Math.random() * 16) | 0;
    var v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16).toUpperCase();
  });
}

var NEW_DEVICE_KEY = uuidv4();
var SEQ = 0;

function log() {
  var args = Array.prototype.slice.call(arguments);
  console.log('[' + (++SEQ) + '] ' + args.join(' '));
}

function spoofKey(key) {
  if (key === 'CFBundleShortVersionString') return SPOOF_SHORT;
  if (key === 'CFBundleVersion') return SPOOF_BUILD;
  return null;
}

function patchDeviceKeyInJsonText(t) {
  if (!t || t.indexOf('device_key') < 0) return null;
  var patched = t.replace(
    /("device_key"\s*:\s*")([0-9A-Fa-f-]{36})(")/g,
    '$1' + NEW_DEVICE_KEY + '$3'
  );
  return patched === t ? null : patched;
}

function dataToUtf8(data) {
  try {
    if (!data || data.isNull() || data.length() === 0) return null;
    var s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
    if (!s) s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 1);
    return s ? s.toString() : null;
  } catch (e) {
    return null;
  }
}

function truncate(t, n) {
  if (!t) return t;
  n = n || 8000;
  return t.length > n ? t.slice(0, n) + '...<truncated ' + t.length + '>' : t;
}

if (!ObjC.available) {
  console.log('[-] ObjC unavailable');
} else {
  log('device_key=' + NEW_DEVICE_KEY);
  log('spoof=' + SPOOF_SHORT + '/' + SPOOF_BUILD);

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

  // Patch device_key when JSON is serialized to Data
  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation, {
    onLeave: function (retval) {
      try {
        var data = ObjC.Object(retval);
        var t = dataToUtf8(data);
        if (!t) return;
        var patched = patchDeviceKeyInJsonText(t);
        if (!patched) return;
        log('PATCH device_key in outgoing JSON');
        retval.replace(ObjC.classes.NSString.stringWithString_(patched).dataUsingEncoding_(4));
      } catch (e) {}
    }
  });

  // Log ALL JSON parsed (responses + configs)
  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
    onEnter: function (args) { this.data = ObjC.Object(args[2]); },
    onLeave: function (retval) {
      try {
        var t = dataToUtf8(this.data);
        if (!t) return;
        // skip huge libphonenumber metadata dumps
        if (t.indexOf('phoneNumberMetadata') >= 0 && t.length > 2000) {
          log('JSON phoneNumberMetadata <skipped len=' + t.length + '>');
          return;
        }
        log('JSON ' + truncate(t, 6000));
      } catch (e) {}
    }
  });

  // Log every NSURLSessionTask resume
  Interceptor.attach(ObjC.classes.NSURLSessionTask['- resume'].implementation, {
    onEnter: function (args) {
      try {
        var task = ObjC.Object(args[0]);
        var req = task.currentRequest() || task.originalRequest();
        if (!req) return;
        var method = req.HTTPMethod().toString();
        var url = req.URL().absoluteString().toString();
        log('REQ ' + method + ' ' + url);
        try {
          var headers = req.allHTTPHeaderFields();
          if (headers) log('HDR ' + truncate(headers.toString(), 2500));
        } catch (e) {}
        try {
          var body = req.HTTPBody();
          var t = dataToUtf8(body);
          if (t) log('BODY ' + truncate(t, 6000));
        } catch (e) {}
      } catch (e) {}
    }
  });

  // Wrap dataTask completion handlers to log response bodies
  try {
    var sel = '- dataTaskWithRequest:completionHandler:';
    Interceptor.attach(ObjC.classes.NSURLSession[sel].implementation, {
      onEnter: function (args) {
        try {
          var req = ObjC.Object(args[2]);
          var url = req.URL().absoluteString().toString();
          var block = new ObjC.Block(args[3]);
          var orig = block.implementation;
          block.implementation = function (data, response, error) {
            try {
              var code = '?';
              var respUrl = url;
              if (response && !response.isNull()) {
                try { code = ObjC.Object(response).statusCode(); } catch (e) {}
                try { respUrl = ObjC.Object(response).URL().absoluteString().toString(); } catch (e) {}
              }
              log('RESP ' + code + ' ' + respUrl);
              if (error && !error.isNull()) {
                log('ERR ' + ObjC.Object(error).localizedDescription().toString());
              }
              var t = dataToUtf8(ObjC.Object(data));
              if (t) {
                if (t.indexOf('phoneNumberMetadata') >= 0 && t.length > 2000) {
                  log('RESPBODY phoneNumberMetadata <skipped len=' + t.length + '>');
                } else {
                  log('RESPBODY ' + truncate(t, 8000));
                }
              }
            } catch (e) {
              log('RESP hook err ' + e);
            }
            return orig(data, response, error);
          };
        } catch (e) {
          log('dataTask wrap err ' + e);
        }
      }
    });
    log('NSURLSession completion hook on');
  } catch (e) {
    log('NSURLSession completion hook failed: ' + e);
  }

  log('full capture ready');
}
