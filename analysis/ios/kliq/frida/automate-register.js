// Full Kliq register automation (ASCII only)
// Prefer: frida -H 192.168.31.167 -n Kliq -l automate_register.js -q -t inf
// Spawn:  frida -H 192.168.31.167 -f tr.com.bpn.kliq -l automate_register.js -q -t inf

var SPOOF_SHORT = '1.30.0';
var SPOOF_BUILD = '1';
var FULL = '447546025969';
var CC = '44';
var NATIONAL = '7546025969';
var REGISTER_X = 302;
var REGISTER_Y = 662;
// UI-first: only fire raw OTP after phone field actually shows the national number
var SKIP_API_OTP = false;

function uuidv4() {
  var s = '';
  var hex = '0123456789ABCDEF';
  for (var i = 0; i < 36; i++) {
    if (i === 8 || i === 13 || i === 18 || i === 23) s += '-';
    else if (i === 14) s += '4';
    else if (i === 19) s += hex[(Math.random() * 4) | 8];
    else s += hex[(Math.random() * 16) | 0];
  }
  return s;
}

var NEW_DEVICE_KEY = uuidv4();
var STEP = 0;
var LAST_TOP = '';
var FILLED = false;
var TAPPED_ACTION = false;
var REGISTER_TAPPED = false;
var REGISTER_ATTEMPTS = 0;
var GOT_TOKEN = false;
var SENT_OTP_API = false;
var STOLEN_TOKEN = null;
var LAST_OTP_JSON = '';
var ACTION_ATTEMPTS = 0;

function spoofKey(key) {
  if (key === 'CFBundleShortVersionString') return SPOOF_SHORT;
  if (key === 'CFBundleVersion') return SPOOF_BUILD;
  return null;
}

function patchDeviceKeyInJsonText(t) {
  if (!t || t.indexOf('device_key') < 0) return null;
  var re = new RegExp('("device_key"\\s*:\\s*")([0-9A-Fa-f-]{36})(")', 'g');
  var patched = t.replace(re, '$1' + NEW_DEVICE_KEY + '$3');
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

function call(obj, sel) {
  var args = Array.prototype.slice.call(arguments, 2);
  var m = obj['- ' + sel];
  if (!m) throw new Error('no method - ' + sel);
  return m.apply(obj, args);
}

function topVC() {
  var app = ObjC.classes.UIApplication.sharedApplication();
  var win = app.keyWindow();
  if (!win) {
    var wins = app.windows();
    if (wins && wins.count() > 0) win = wins.objectAtIndex_(0);
  }
  if (!win) return null;
  var vc = win.rootViewController();
  while (vc) {
    if (vc.presentedViewController()) {
      vc = vc.presentedViewController();
      continue;
    }
    if (vc.isKindOfClass_(ObjC.classes.UINavigationController) && vc.visibleViewController()) {
      vc = vc.visibleViewController();
      continue;
    }
    if (vc.isKindOfClass_(ObjC.classes.UITabBarController) && vc.selectedViewController()) {
      vc = vc.selectedViewController();
      continue;
    }
    break;
  }
  return vc;
}

function keyWindow() {
  var app = ObjC.classes.UIApplication.sharedApplication();
  var win = app.keyWindow();
  if (!win) {
    var wins = app.windows();
    if (wins && wins.count() > 0) win = wins.objectAtIndex_(0);
  }
  return win;
}

function parseFrameFromDesc(desc) {
  var m = /frame\s*=\s*\(([-\d.]+)\s+([-\d.]+);\s*([-\d.]+)\s+([-\d.]+)\)/.exec(desc || '');
  if (!m) return null;
  return { x: parseFloat(m[1]), y: parseFloat(m[2]), w: parseFloat(m[3]), h: parseFloat(m[4]) };
}

function collectHitViews(v, depth, out) {
  if (!v || depth > 18 || out.length > 220) return;
  var cls = v.$className || '';
  var interesting =
    cls.indexOf('HitTesting') >= 0 ||
    cls.indexOf('Button') >= 0 ||
    cls.indexOf('TextField') >= 0 ||
    cls.indexOf('Label') >= 0 ||
    cls.indexOf('Hosting') >= 0;
  if (interesting) {
    var fr = null;
    try {
      fr = parseFrameFromDesc(v.description().toString());
    } catch (e) {}
    var bits = [];
    try {
      if (v.respondsToSelector_(ObjC.selector('text')) && v.text()) {
        bits.push('text=' + JSON.stringify(v.text().toString().slice(0, 80)));
      }
    } catch (e) {}
    try {
      if (v.respondsToSelector_(ObjC.selector('placeholder')) && v.placeholder()) {
        bits.push('ph=' + JSON.stringify(v.placeholder().toString().slice(0, 80)));
      }
    } catch (e) {}
    try {
      if (v.respondsToSelector_(ObjC.selector('currentTitle')) && v.currentTitle()) {
        bits.push('title=' + JSON.stringify(v.currentTitle().toString().slice(0, 80)));
      }
    } catch (e) {}
    try {
      if (v.respondsToSelector_(ObjC.selector('accessibilityLabel')) && v.accessibilityLabel()) {
        bits.push('a11y=' + JSON.stringify(v.accessibilityLabel().toString().slice(0, 80)));
      }
    } catch (e) {}
    out.push({ view: v, cls: cls, depth: depth, fr: fr, bits: bits.join(' ') });
  }
  try {
    var subs = v.subviews();
    for (var i = 0; i < subs.count(); i++) collectHitViews(subs.objectAtIndex_(i), depth + 1, out);
  } catch (e) {}
}

function dumpUI(tag) {
  var vc = topVC();
  var name = vc ? vc.$className : 'null';
  console.log('==== UI ' + tag + ' TOP=' + name);
  if (!vc) return [];
  var out = [];
  collectHitViews(vc.view(), 0, out);
  for (var i = 0; i < out.length; i++) {
    var row = out[i];
    var pad = '';
    for (var d = 0; d < Math.min(row.depth, 8); d++) pad += '  ';
    var frs = row.fr
      ? ' frame=(' + row.fr.x.toFixed(1) + ' ' + row.fr.y.toFixed(1) + '; ' + row.fr.w.toFixed(1) + ' ' + row.fr.h.toFixed(1) + ')'
      : '';
    console.log(pad + row.cls + frs + (row.bits ? ' | ' + row.bits : ''));
  }
  return out;
}

function setTextField(tf, value) {
  ObjC.schedule(ObjC.mainQueue, function () {
    try {
      tf.becomeFirstResponder();
      // Prefer ObjC bridge method forms that work on this Frida
      if (tf['- setText:']) tf['- setText:'](value);
      else tf.setText_(value);
      try {
        if (tf['- sendActionsForControlEvents:']) tf['- sendActionsForControlEvents:'](65536);
        else tf.sendActionsForControlEvents_(65536);
      } catch (e2) {}
      // Notify SwiftUI/UIKit observers
      try {
        ObjC.classes.NSNotificationCenter.defaultCenter().postNotificationName_object_(
          'UITextFieldTextDidChangeNotification',
          tf
        );
      } catch (e3) {}
      var now = '';
      try {
        now = tf.text() ? tf.text().toString() : '';
      } catch (e4) {}
      console.log('[UI] setTextField -> ' + value + ' (now=' + now + ')');
    } catch (e) {
      console.log('[UI] setText err ' + e);
    }
  });
}

function tapButton(btn) {
  ObjC.schedule(ObjC.mainQueue, function () {
    try {
      btn.sendActionsForControlEvents_(64);
      var t = '';
      try {
        t = btn.currentTitle() ? btn.currentTitle().toString() : '';
      } catch (e) {}
      console.log('[UI] tapped UIButton ' + t);
    } catch (e) {
      console.log('[UI] tap UIButton err ' + e);
    }
  });
}

function looksLikeAction(bits) {
  var s = (bits || '').toLowerCase();
  return (
    s.indexOf('continue') >= 0 ||
    s.indexOf('next') >= 0 ||
    s.indexOf('send') >= 0 ||
    s.indexOf('confirm') >= 0 ||
    s.indexOf('done') >= 0 ||
    s.indexOf('register') >= 0 ||
    s.indexOf('sign up') >= 0 ||
    s.indexOf('get code') >= 0 ||
    s.indexOf('otp') >= 0 ||
    s.indexOf('kayit') >= 0 ||
    s.indexOf('devam') >= 0
  );
}

// Proven path from probe: private UITouch + UIApplication._touchesEvent + sendEvent
function tapAt(x, y, reason) {
  ObjC.schedule(ObjC.mainQueue, function () {
    try {
      console.log('[TAP] ' + reason + ' @ (' + x.toFixed(1) + ',' + y.toFixed(1) + ')');
      var app = ObjC.classes.UIApplication.sharedApplication();
      var win = keyWindow();
      if (!win) {
        console.log('[TAP] no window');
        return;
      }
      var view = win.hitTest_withEvent_([x, y], NULL);
      if (!view || view.isNull()) {
        console.log('[TAP] hitTest null');
        return;
      }
      console.log('[TAP] hit=' + view.$className);

      var touch = ObjC.classes.UITouch.alloc().init();
      call(touch, 'setWindow:', win);
      call(touch, 'setView:', view);
      call(touch, 'setTapCount:', 1);
      call(touch, 'setTimestamp:', ObjC.classes.NSProcessInfo.processInfo().systemUptime());
      call(touch, 'setPhase:', 0);
      try {
        call(touch, '_setLocationInWindow:resetPrevious:', [x, y], 1);
      } catch (e) {
        console.log('[TAP] setLocation err ' + e);
      }
      try {
        call(touch, '_setIsFirstTouchForView:', 1);
      } catch (e) {}

      var event = call(app, '_touchesEvent');
      try {
        if (event['- _clearTouches']) call(event, '_clearTouches');
      } catch (e) {}
      call(event, '_addTouch:forDelayedDelivery:', touch, 0);
      call(app, 'sendEvent:', event);
      call(touch, 'setPhase:', 3);
      try {
        call(touch, '_setLocationInWindow:resetPrevious:', [x, y], 0);
      } catch (e) {}
      call(app, 'sendEvent:', event);
      console.log('[TAP] sendEvent began+ended OK');
    } catch (e) {
      console.log('[TAP] ERR ' + e);
    }
  });
}

function findRegisterTarget(rows) {
  var best = null;
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    if (!r.fr) continue;
    if (r.cls.indexOf('HitTesting') < 0 && r.cls.indexOf('Button') < 0) continue;
    if (r.fr.y > 580 && r.fr.x > 180 && r.fr.w > 100 && r.fr.h > 40) {
      if (!best || r.fr.x > best.fr.x) best = r;
    }
  }
  return best;
}

function findBottomActionTargets(rows) {
  var hits = [];
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    if (!r.fr) continue;
    if (r.cls.indexOf('HitTesting') < 0 && r.cls.indexOf('Button') < 0) continue;
    if (r.fr.y > 560 && r.fr.w > 80 && r.fr.h > 35) hits.push(r);
  }
  hits.sort(function (a, b) {
    return b.fr.y - a.fr.y || b.fr.w - a.fr.w;
  });
  return hits;
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
        console.log('[HTTP] ' + method + ' ' + url + ' -> ' + code);
        console.log('[HTTP-BODY] ' + text.slice(0, 4000));
        if (cb) cb(code, text);
      }
    })
  );
  task.resume();
}

function sendOtpApiOnce(token) {
  if (SENT_OTP_API) return;
  if (SKIP_API_OTP) {
    console.log('[API] SKIP_API_OTP=true ? not calling SendOtpSms2');
    SENT_OTP_API = true;
    return;
  }
  SENT_OTP_API = true;
  console.log('[API] sending OTP once to ' + FULL);
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
        function () {
          console.log('[API] OTP request finished - watch SMS on +' + CC + ' ' + NATIONAL);
        }
      );
    }
  );
}

function maybeRegisterTap(rows, top) {
  if (REGISTER_TAPPED) return;
  if (top.indexOf('OnboardingMainView') < 0) return;
  if (REGISTER_ATTEMPTS >= 6) return;

  REGISTER_ATTEMPTS++;
  var target = findRegisterTarget(rows);
  var cx = REGISTER_X;
  var cy = REGISTER_Y;
  if (target && target.fr) {
    cx = target.fr.x + target.fr.w / 2;
    cy = target.fr.y + target.fr.h / 2;
    console.log('[REG] attempt ' + REGISTER_ATTEMPTS + ' hit-view center=(' + cx.toFixed(1) + ',' + cy.toFixed(1) + ')');
  } else {
    console.log('[REG] attempt ' + REGISTER_ATTEMPTS + ' fallback coords');
  }
  tapAt(cx, cy, 'Register');
  REGISTER_TAPPED = true;
  setTimeout(function () {
    var vc = topVC();
    var name = vc ? vc.$className : '';
    if (name.indexOf('OnboardingMainView') >= 0 && REGISTER_ATTEMPTS < 6) {
      console.log('[REG] still onboarding - retry');
      REGISTER_TAPPED = false;
    } else {
      console.log('[REG] left onboarding -> ' + name);
    }
  }, 2500);
}

function tick() {
  var rows = dumpUI('step' + STEP);
  var vc = topVC();
  var top = vc ? vc.$className : '';
  if (top !== LAST_TOP) {
    console.log('[UI] screen changed -> ' + top);
    LAST_TOP = top;
    FILLED = false;
    TAPPED_ACTION = false;
    ACTION_ATTEMPTS = 0;
    if (top.indexOf('OnboardingMainView') >= 0) REGISTER_TAPPED = false;
  }

  maybeRegisterTap(rows, top);

  // Exact UITextField only ? UITextFieldLabel also contains the substring
  var fields = [];
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].cls === 'UITextField') fields.push(rows[i]);
  }

  if (fields.length >= 1 && !FILLED) {
    // Phone screen has one national field (ph="___ ___ __ __"); CC is a separate picker
    if (fields.length === 1) {
      setTextField(fields[0].view, NATIONAL);
    } else {
      setTextField(fields[0].view, CC);
      setTextField(fields[fields.length - 1].view, NATIONAL);
    }
    FILLED = true;
  }

  // After fill, tap continue / send via UIButton or SwiftUI hit-view
  if (FILLED && !TAPPED_ACTION && ACTION_ATTEMPTS < 5) {
    var did = false;
    for (var j = 0; j < rows.length; j++) {
      if (rows[j].cls.indexOf('UIButton') >= 0 && looksLikeAction(rows[j].bits)) {
        tapButton(rows[j].view);
        did = true;
        break;
      }
    }
    if (!did) {
      var actions = findBottomActionTargets(rows);
      if (actions.length) {
        var a = actions[0];
        var cx = a.fr.x + a.fr.w / 2;
        var cy = a.fr.y + a.fr.h / 2;
        tapAt(cx, cy, 'post-fill-action');
        did = true;
      }
    }
    if (did) {
      ACTION_ATTEMPTS++;
      TAPPED_ACTION = true;
      setTimeout(function () {
        // allow retry if still same screen with fields
        var vc2 = topVC();
        var n2 = vc2 ? vc2.$className : '';
        if (n2 === LAST_TOP && ACTION_ATTEMPTS < 5) {
          console.log('[UI] action retry armed');
          TAPPED_ACTION = false;
        }
      }, 3000);
    }
  }

  if (top.indexOf('Alert') >= 0) {
    for (var a = 0; a < rows.length; a++) {
      if ((rows[a].bits || '').indexOf('text=') >= 0) console.log('[ALERT] ' + rows[a].bits);
    }
  }

  // Backup raw OTP only after UITextField shows our national digits
  if (STOLEN_TOKEN && FILLED && !SENT_OTP_API && STEP > 4) {
    var hasText = false;
    for (var t = 0; t < rows.length; t++) {
      if (rows[t].cls !== 'UITextField') continue;
      var bits = rows[t].bits || '';
      if (bits.indexOf(NATIONAL) >= 0 || bits.indexOf(FULL) >= 0) {
        hasText = true;
        break;
      }
    }
    if (hasText) {
      console.log('[API] UI phone shows target - firing raw OTP once as backup');
      sendOtpApiOnce(STOLEN_TOKEN);
    } else {
      console.log('[UI] waiting for phone field to show ' + NATIONAL);
    }
  }

  STEP++;
}

if (ObjC.available) {
  var NSBundle = ObjC.classes.NSBundle;
  Interceptor.attach(NSBundle['- objectForInfoDictionaryKey:'].implementation, {
    onEnter: function (args) {
      this.key = ObjC.Object(args[2]).toString();
    },
    onLeave: function (retval) {
      var v = spoofKey(this.key);
      if (v) retval.replace(ObjC.classes.NSString.stringWithString_(v));
    }
  });

  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation, {
    onLeave: function (retval) {
      try {
        var data = ObjC.Object(retval);
        if (!data || data.isNull()) return;
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
        if (!s) return;
        var patched = patchDeviceKeyInJsonText(s.toString());
        if (patched) {
          retval.replace(ObjC.classes.NSString.stringWithString_(patched).dataUsingEncoding_(4));
          console.log('[DK] patched device_key -> ' + NEW_DEVICE_KEY);
        }
      } catch (e) {}
    }
  });

  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
    onEnter: function (args) {
      this.data = ObjC.Object(args[2]);
    },
    onLeave: function (retval) {
      try {
        var t = dataToUtf8(this.data);
        if (!t) return;
        if (!GOT_TOKEN && t.indexOf('access_token') >= 0) {
          try {
            var j = JSON.parse(t);
            if (j && j.access_token) {
              GOT_TOKEN = true;
              STOLEN_TOKEN = j.access_token;
              console.log('[+] stole access_token len=' + STOLEN_TOKEN.length);
            }
          } catch (e) {}
        }
        if (
          t.length < 4000 &&
          (t.indexOf('otp') >= 0 ||
            t.indexOf('sms') >= 0 ||
            t.indexOf('310') >= 0 ||
            t.indexOf('312') >= 0 ||
            t.indexOf('phone') >= 0 ||
            t.indexOf('minute') >= 0 ||
            t.indexOf('Dogrulama') >= 0 ||
            t.indexOf('gonderimi') >= 0)
        ) {
          if (t !== LAST_OTP_JSON) {
            LAST_OTP_JSON = t;
            console.log('[JSON] ' + t);
          }
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
        var url = req.URL() ? req.URL().absoluteString().toString() : '';
        if (
          url.indexOf('RegisterPersonalAccountSendOtpSms2') >= 0 ||
          url.indexOf('CheckPhoneNumberIsExist') >= 0 ||
          url.indexOf('initialize') >= 0 ||
          url.indexOf('Register') >= 0
        ) {
          console.log('[REQ] ' + req.HTTPMethod().toString() + ' ' + url);
          var body = req.HTTPBody();
          var bt = dataToUtf8(body);
          if (bt) console.log('[REQ-BODY] ' + bt.slice(0, 800));
        }
        if (!GOT_TOKEN) {
          var headers = req.allHTTPHeaderFields();
          if (headers) {
            var auth = headers.objectForKey_('Authorization');
            if (auth) {
              var a = auth.toString();
              if (a.indexOf('Bearer ') === 0) {
                GOT_TOKEN = true;
                STOLEN_TOKEN = a.slice(7);
                console.log('[+] stole Bearer from request len=' + STOLEN_TOKEN.length);
              }
            }
          }
        }
      } catch (e) {}
    }
  });

  console.log('[+] automate_register ready for +' + CC + ' ' + NATIONAL);
  console.log('[+] device_key ' + NEW_DEVICE_KEY);
  setTimeout(function () {
    var rows = dumpUI('boot');
    var vc = topVC();
    maybeRegisterTap(rows, vc ? vc.$className : '');
    setInterval(tick, 2500);
  }, 1200);
}
