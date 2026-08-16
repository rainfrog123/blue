// One-shot: spoof + Register tap, then leave app on phone screen.
// frida -H 192.168.31.167 -f tr.com.bpn.kliq -l boot_to_phone.js -q -t 60

var SPOOF_SHORT = '1.30.0';
var SPOOF_BUILD = '1';
var DONE = false;

function uuidv4() {
  var s = '', hex = '0123456789ABCDEF';
  for (var i = 0; i < 36; i++) {
    if (i === 8 || i === 13 || i === 18 || i === 23) s += '-';
    else if (i === 14) s += '4';
    else if (i === 19) s += hex[(Math.random() * 4) | 8];
    else s += hex[(Math.random() * 16) | 0];
  }
  return s;
}
var NEW_DEVICE_KEY = uuidv4();

function call(obj, sel) {
  var args = Array.prototype.slice.call(arguments, 2);
  return obj['- ' + sel].apply(obj, args);
}

function topVC() {
  var app = ObjC.classes.UIApplication.sharedApplication();
  var win = app.keyWindow() || app.windows().objectAtIndex_(0);
  var vc = win.rootViewController();
  while (vc) {
    if (vc.presentedViewController()) { vc = vc.presentedViewController(); continue; }
    if (vc.isKindOfClass_(ObjC.classes.UINavigationController) && vc.visibleViewController()) {
      vc = vc.visibleViewController(); continue;
    }
    break;
  }
  return vc;
}

function parseFrame(desc) {
  var m = /frame\s*=\s*\(([-\d.]+)\s+([-\d.]+);\s*([-\d.]+)\s+([-\d.]+)\)/.exec(desc || '');
  if (!m) return null;
  return { x: +m[1], y: +m[2], w: +m[3], h: +m[4] };
}

function tapAt(x, y) {
  var app = ObjC.classes.UIApplication.sharedApplication();
  var win = app.keyWindow();
  var view = win.hitTest_withEvent_([x, y], NULL);
  console.log('[TAP] hit=' + (view ? view.$className : 'null'));
  var touch = ObjC.classes.UITouch.alloc().init();
  call(touch, 'setWindow:', win);
  call(touch, 'setView:', view);
  call(touch, 'setTapCount:', 1);
  call(touch, 'setTimestamp:', ObjC.classes.NSProcessInfo.processInfo().systemUptime());
  call(touch, 'setPhase:', 0);
  call(touch, '_setLocationInWindow:resetPrevious:', [x, y], 1);
  try { call(touch, '_setIsFirstTouchForView:', 1); } catch (e) {}
  var event = call(app, '_touchesEvent');
  try { if (event['- _clearTouches']) call(event, '_clearTouches'); } catch (e) {}
  call(event, '_addTouch:forDelayedDelivery:', touch, 0);
  call(app, 'sendEvent:', event);
  call(touch, 'setPhase:', 3);
  call(app, 'sendEvent:', event);
}

function findRegister(root) {
  var best = null;
  function walk(v, d) {
    if (!v || d > 20) return;
    if ((v.$className || '').indexOf('HitTesting') >= 0) {
      var fr = parseFrame(v.description().toString());
      if (fr && fr.y > 580 && fr.x > 180 && fr.w > 100) {
        if (!best || fr.x > best.fr.x) best = { v: v, fr: fr };
      }
    }
    try {
      var s = v.subviews();
      for (var i = 0; i < s.count(); i++) walk(s.objectAtIndex_(i), d + 1);
    } catch (e) {}
  }
  walk(root, 0);
  return best;
}

if (ObjC.available) {
  Interceptor.attach(ObjC.classes.NSBundle['- objectForInfoDictionaryKey:'].implementation, {
    onEnter: function (args) { this.key = ObjC.Object(args[2]).toString(); },
    onLeave: function (retval) {
      if (this.key === 'CFBundleShortVersionString') retval.replace(ObjC.classes.NSString.stringWithString_(SPOOF_SHORT));
      if (this.key === 'CFBundleVersion') retval.replace(ObjC.classes.NSString.stringWithString_(SPOOF_BUILD));
    }
  });
  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ dataWithJSONObject:options:error:'].implementation, {
    onLeave: function (retval) {
      try {
        var data = ObjC.Object(retval);
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
        if (!s) return;
        var t = s.toString();
        if (t.indexOf('device_key') < 0) return;
        var patched = t.replace(/("device_key"\s*:\s*")([0-9A-Fa-f-]{36})(")/g, '$1' + NEW_DEVICE_KEY + '$3');
        if (patched !== t) retval.replace(ObjC.classes.NSString.stringWithString_(patched).dataUsingEncoding_(4));
      } catch (e) {}
    }
  });

  console.log('[+] boot_to_phone device_key=' + NEW_DEVICE_KEY);
  var n = 0;
  var iv = setInterval(function () {
    n++;
    ObjC.schedule(ObjC.mainQueue, function () {
      var vc = topVC();
      var name = vc ? vc.$className : 'null';
      console.log('[BOOT] ' + n + ' TOP=' + name);
      if (DONE) return;
      if (name.indexOf('OnboardingMainView') >= 0) {
        var reg = findRegister(vc.view());
        var x = 302, y = 662;
        if (reg) { x = reg.fr.x + reg.fr.w / 2; y = reg.fr.y + reg.fr.h / 2; }
        console.log('[BOOT] tapping Register ' + x + ',' + y);
        tapAt(x, y);
      }
      if (name.indexOf('OnboardingMainView') < 0 && name.indexOf('SplashView') < 0 && name.indexOf('null') < 0) {
        DONE = true;
        console.log('[BOOT] phone screen ready - leave Frida, keep Kliq, hot-attach fill probes');
        clearInterval(iv);
      }
    });
    if (n > 40) clearInterval(iv);
  }, 1500);
}
