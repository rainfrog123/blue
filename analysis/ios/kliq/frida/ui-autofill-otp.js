// UI dump + autofill phone for Kliq signup (ASCII only)
// frida -H 192.168.31.167 -f tr.com.bpn.kliq -l ui_autofill_otp.js -q -t inf

var SPOOF_SHORT = '1.30.0';
var SPOOF_BUILD = '1';
var FULL = '447754994724';
var CC = '44';
var NATIONAL = '7754994724';

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
var TAPPED = false;

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

function collectUI(v, depth, out) {
  if (!v || depth > 14 || out.length > 120) return;
  var cls = v.$className;
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
  if (bits.length || cls.indexOf('TextField') >= 0 || cls.indexOf('Button') >= 0 || cls.indexOf('Label') >= 0) {
    out.push({ view: v, cls: cls, depth: depth, bits: bits.join(' ') });
  }
  try {
    var subs = v.subviews();
    for (var i = 0; i < subs.count(); i++) collectUI(subs.objectAtIndex_(i), depth + 1, out);
  } catch (e) {}
}

function dumpUI(tag) {
  var vc = topVC();
  var name = vc ? vc.$className : 'null';
  console.log('==== UI ' + tag + ' TOP=' + name);
  if (!vc) return [];
  var out = [];
  collectUI(vc.view(), 0, out);
  for (var i = 0; i < out.length; i++) {
    var row = out[i];
    var pad = '';
    for (var d = 0; d < row.depth; d++) pad += '  ';
    console.log(pad + row.cls + (row.bits ? ' | ' + row.bits : ''));
  }
  return out;
}

function setTextField(tf, value) {
  ObjC.schedule(ObjC.mainQueue, function () {
    try {
      tf.becomeFirstResponder();
      tf.setText_(value);
      tf.sendActionsForControlEvents_(65536);
      console.log('[UI] set TextField -> ' + value);
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
      try { t = btn.currentTitle() ? btn.currentTitle().toString() : ''; } catch (e) {}
      console.log('[UI] tapped button ' + t);
    } catch (e) {
      console.log('[UI] tap err ' + e);
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
    s.indexOf('otp') >= 0
  );
}

function tick() {
  var rows = dumpUI('step' + STEP);
  var vc = topVC();
  var top = vc ? vc.$className : '';
  if (top !== LAST_TOP) {
    console.log('[UI] screen changed -> ' + top);
    LAST_TOP = top;
    FILLED = false;
    TAPPED = false;
  }

  var fields = [];
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].cls.indexOf('UITextField') >= 0) fields.push(rows[i]);
  }

  if (fields.length >= 1 && !FILLED) {
    if (fields.length === 1) {
      setTextField(fields[0].view, NATIONAL);
    } else {
      setTextField(fields[0].view, CC);
      setTextField(fields[1].view, NATIONAL);
    }
    FILLED = true;
  }

  if (FILLED && !TAPPED) {
    for (var j = 0; j < rows.length; j++) {
      if (rows[j].cls.indexOf('UIButton') >= 0 && looksLikeAction(rows[j].bits)) {
        tapButton(rows[j].view);
        TAPPED = true;
        break;
      }
    }
  }

  if (top.indexOf('Alert') >= 0) {
    for (var k = 0; k < rows.length; k++) {
      if ((rows[k].bits || '').indexOf('text=') >= 0) console.log('[ALERT] ' + rows[k].bits);
    }
  }

  STEP++;
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
        var data = ObjC.Object(retval);
        if (!data || data.isNull()) return;
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
        if (!s) return;
        var patched = patchDeviceKeyInJsonText(s.toString());
        if (patched) {
          retval.replace(ObjC.classes.NSString.stringWithString_(patched).dataUsingEncoding_(4));
        }
      } catch (e) {}
    }
  });

  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
    onEnter: function (args) { this.data = ObjC.Object(args[2]); },
    onLeave: function (retval) {
      try {
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(ObjC.Object(this.data), 4);
        if (!s) return;
        var t = s.toString();
        if (t.length < 2000 && (t.indexOf('otp') >= 0 || t.indexOf('sms') >= 0 || t.indexOf('310') >= 0 || t.indexOf('312') >= 0 || t.indexOf('phone') >= 0 || t.indexOf('minute') >= 0)) {
          console.log('[JSON] ' + t);
        }
      } catch (e) {}
    }
  });

  console.log('[+] UI autofill ready for +' + CC + ' ' + NATIONAL);
  console.log('[+] device_key ' + NEW_DEVICE_KEY);
  setTimeout(function () {
    dumpUI('boot');
    setInterval(tick, 4000);
  }, 3000);
}
