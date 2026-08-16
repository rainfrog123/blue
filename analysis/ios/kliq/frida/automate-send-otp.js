// Wait for app's own Bearer token, then send OTP once for fixed MSISDN.
// frida -H 192.168.31.167 -f tr.com.bpn.kliq -l automate_send_otp.js -q -t 90

var SPOOF_SHORT = '1.30.0';
var SPOOF_BUILD = '1';
var FULL = '447754994724';
var CC = '44';
var NATIONAL = '7754994724';

function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    var r = (Math.random() * 16) | 0;
    var v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16).toUpperCase();
  });
}

var NEW_DEVICE_KEY = uuidv4();
var GOT_TOKEN = false;
var SENT_OTP = false;

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
    if (!s) return null;
    return s.toString();
  } catch (e) {
    return null;
  }
}

function httpJson(method, url, bearer, bodyObj, cb) {
  var req = ObjC.classes.NSMutableURLRequest.requestWithURL_(
    ObjC.classes.NSURL.URLWithString_(url)
  );
  req.setHTTPMethod_(method);
  req.setValue_forHTTPHeaderField_('application/json', 'Content-Type');
  req.setValue_forHTTPHeaderField_('application/json', 'Accept');
  req.setValue_forHTTPHeaderField_('IOS', 'X-Platform');
  req.setValue_forHTTPHeaderField_(SPOOF_SHORT, 'X-Version');
  req.setValue_forHTTPHeaderField_('en', 'X-Locale');
  req.setValue_forHTTPHeaderField_('en', 'Locale');
  req.setValue_forHTTPHeaderField_(
    'Kliq/' + SPOOF_SHORT + ' (tr.com.bpn.kliq; build:' + SPOOF_BUILD + '; iOS 15.7.1) Alamofire/5.10.2',
    'User-Agent'
  );
  if (bearer) req.setValue_forHTTPHeaderField_('Bearer ' + bearer, 'Authorization');
  if (bodyObj !== null && bodyObj !== undefined) {
    var bodyStr = JSON.stringify(bodyObj);
    req.setHTTPBody_(ObjC.classes.NSString.stringWithString_(bodyStr).dataUsingEncoding_(4));
  }
  var task = ObjC.classes.NSURLSession.sharedSession().dataTaskWithRequest_completionHandler_(
    req,
    new ObjC.Block({
      retType: 'void',
      argTypes: ['object', 'object', 'object'],
      implementation: function (data, response, error) {
        var code = '?';
        try {
          if (response && !response.isNull()) code = ObjC.Object(response).statusCode();
        } catch (e) {}
        var text = dataToUtf8(ObjC.Object(data)) || '';
        if (error && !error.isNull()) {
          console.log('[HTTP-ERR] ' + ObjC.Object(error).localizedDescription().toString());
        }
        console.log('[HTTP] ' + method + ' ' + url + ' → ' + code);
        console.log('[HTTP-BODY] ' + text.slice(0, 4000));
        if (cb) cb(code, text);
      }
    })
  );
  task.resume();
}

function sendOtpOnce(token) {
  if (SENT_OTP) return;
  SENT_OTP = true;
  console.log('[*] sending OTP once to ' + FULL);

  httpJson(
    'POST',
    'https://mobilegateway.kliq.com.tr/v1/app/initialize',
    token,
    { device: { device_key: NEW_DEVICE_KEY, brand: 'Apple', model: 'iPhone8,2', os_version: '15.7.1' } },
    function () {
      httpJson(
        'POST',
        'https://mobilegateway.kliq.com.tr/Account/CheckPhoneNumberIsExist',
        token,
        { phone_country_code: CC, phone_number: NATIONAL },
        function () {
          httpJson(
            'POST',
            'https://mobilegateway.kliq.com.tr/Account/RegisterPersonalAccountSendOtpSms2',
            token,
            { phone_number: FULL },
            function (code, text) {
              console.log('[*] OTP done. Watch SMS on ' + FULL);
            }
          );
        }
      );
    }
  );
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

  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation, {
    onLeave: function (retval) {
      try {
        var t = dataToUtf8(ObjC.Object(retval));
        if (!t) return;
        var patched = patchDeviceKeyInJsonText(t);
        if (patched) {
          retval.replace(ObjC.classes.NSString.stringWithString_(patched).dataUsingEncoding_(4));
        }
      } catch (e) {}
    }
  });

  // Steal access_token from app's own JSON parses
  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
    onEnter: function (args) { this.data = ObjC.Object(args[2]); },
    onLeave: function (retval) {
      if (GOT_TOKEN) return;
      try {
        var t = dataToUtf8(this.data);
        if (!t || t.indexOf('access_token') < 0) return;
        var j = JSON.parse(t);
        if (j && j.access_token) {
          GOT_TOKEN = true;
          console.log('[+] stole app access_token len=' + j.access_token.length);
          // small delay so initialize can finish naturally first
          setTimeout(function () { sendOtpOnce(j.access_token); }, 2500);
        }
      } catch (e) {}
    }
  });

  // Also watch Authorization headers on resume as backup
  Interceptor.attach(ObjC.classes.NSURLSessionTask['- resume'].implementation, {
    onEnter: function (args) {
      if (GOT_TOKEN) return;
      try {
        var task = ObjC.Object(args[0]);
        var req = task.currentRequest() || task.originalRequest();
        if (!req) return;
        var headers = req.allHTTPHeaderFields();
        if (!headers) return;
        var auth = headers.objectForKey_('Authorization');
        if (!auth) return;
        var a = auth.toString();
        if (a.indexOf('Bearer ') === 0) {
          GOT_TOKEN = true;
          var token = a.slice(7);
          console.log('[+] stole Bearer from request len=' + token.length);
          setTimeout(function () { sendOtpOnce(token); }, 2500);
        }
      } catch (e) {}
    }
  });

  console.log('[+] automate OTP for ' + FULL);
  console.log('[+] device_key ' + NEW_DEVICE_KEY);
  console.log('[+] waiting for app token...');
}
