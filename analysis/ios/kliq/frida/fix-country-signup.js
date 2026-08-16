// HOT-ATTACH: fix country to +44, keep phone, tap Sign Up
// frida -H 192.168.31.167 -n Kliq -l fix_country_signup.js -q -t 90

var NATIONAL = '7546025969';
var WANT_CC = '44';
var STEP = 'dump'; // dump -> tapCC -> search/pick -> refill -> signup

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
    if (vc.isKindOfClass_(ObjC.classes.UITabBarController) && vc.selectedViewController()) {
      vc = vc.selectedViewController(); continue;
    }
    break;
  }
  return vc;
}

function keyWindow() {
  var app = ObjC.classes.UIApplication.sharedApplication();
  return app.keyWindow() || app.windows().objectAtIndex_(0);
}

function parseFrame(desc) {
  var m = /frame\s*=\s*\(([-\d.]+)\s+([-\d.]+);\s*([-\d.]+)\s+([-\d.]+)\)/.exec(desc || '');
  if (!m) return null;
  return { x: +m[1], y: +m[2], w: +m[3], h: +m[4] };
}

function tapAt(x, y, reason) {
  console.log('[TAP] ' + reason + ' @ (' + x.toFixed(1) + ',' + y.toFixed(1) + ')');
  var app = ObjC.classes.UIApplication.sharedApplication();
  var win = keyWindow();
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

function collect(v, depth, out) {
  if (!v || depth > 22 || out.length > 250) return;
  var cls = v.$className || '';
  var bits = [];
  var fr = null;
  try { fr = parseFrame(v.description().toString()); } catch (e) {}
  try {
    if (v.respondsToSelector_(ObjC.selector('text')) && v.text()) {
      bits.push('text=' + JSON.stringify(v.text().toString().slice(0, 120)));
    }
  } catch (e) {}
  try {
    if (v.respondsToSelector_(ObjC.selector('placeholder')) && v.placeholder()) {
      bits.push('ph=' + JSON.stringify(v.placeholder().toString().slice(0, 80)));
    }
  } catch (e) {}
  try {
    if (v.respondsToSelector_(ObjC.selector('accessibilityLabel')) && v.accessibilityLabel()) {
      bits.push('a11y=' + JSON.stringify(v.accessibilityLabel().toString().slice(0, 80)));
    }
  } catch (e) {}
  var interesting =
    cls.indexOf('HitTesting') >= 0 ||
    cls.indexOf('TextField') >= 0 ||
    cls.indexOf('Label') >= 0 ||
    cls.indexOf('Button') >= 0 ||
    cls.indexOf('Search') >= 0 ||
    cls.indexOf('Table') >= 0 ||
    cls.indexOf('Cell') >= 0 ||
    bits.length > 0;
  if (interesting) out.push({ v: v, cls: cls, fr: fr, bits: bits.join(' '), depth: depth });
  try {
    var s = v.subviews();
    for (var i = 0; i < s.count(); i++) collect(s.objectAtIndex_(i), depth + 1, out);
  } catch (e) {}
}

function dump(tag) {
  var vc = topVC();
  console.log('==== ' + tag + ' TOP=' + (vc ? vc.$className : 'null'));
  var out = [];
  if (vc) collect(vc.view(), 0, out);
  // also scan key window for presented sheets
  try {
    var win = keyWindow();
    collect(win, 0, out);
  } catch (e) {}
  for (var i = 0; i < out.length; i++) {
    var r = out[i];
    var frs = r.fr ? ' frame=(' + r.fr.x.toFixed(1) + ' ' + r.fr.y.toFixed(1) + '; ' + r.fr.w.toFixed(1) + ' ' + r.fr.h.toFixed(1) + ')' : '';
    if (r.bits || (r.cls.indexOf('HitTesting') >= 0) || r.cls === 'UITextField') {
      console.log(r.cls + frs + (r.bits ? ' | ' + r.bits : ''));
    }
  }
  return out;
}

function fillInsert(tf, value) {
  tf.becomeFirstResponder();
  try {
    var cur = tf.text() ? tf.text().toString() : '';
    for (var i = 0; i < cur.length + 8; i++) {
      if (tf['- deleteBackward']) tf['- deleteBackward']();
    }
  } catch (e) {}
  for (var j = 0; j < value.length; j++) tf['- insertText:'](value.charAt(j));
  console.log('[FILL] now=' + (tf.text() ? tf.text().toString() : ''));
}

function findPhoneField(rows) {
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].cls === 'UITextField') return rows[i].v;
  }
  return null;
}

function findCountryHit(rows) {
  // left phone-row hit ~ (23.5 158.5; 114x53) from earlier dump
  var best = null;
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    if (!r.fr) continue;
    if (r.cls.indexOf('HitTesting') < 0) continue;
    if (r.fr.y > 140 && r.fr.y < 220 && r.fr.x < 80 && r.fr.w > 80 && r.fr.w < 160) {
      best = r;
      break;
    }
  }
  return best;
}

function findSignUpHit(rows) {
  // look for bits containing Sign Up, or wide bottom-ish button above keyboard
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    var b = (r.bits || '').toLowerCase();
    if (b.indexOf('sign up') >= 0 || b.indexOf('signup') >= 0) return r;
  }
  var candidates = [];
  for (var j = 0; j < rows.length; j++) {
    var r2 = rows[j];
    if (!r2.fr) continue;
    if (r2.cls.indexOf('HitTesting') < 0) continue;
    if (r2.fr.w > 250 && r2.fr.h > 40 && r2.fr.h < 80 && r2.fr.y > 250 && r2.fr.y < 520) {
      candidates.push(r2);
    }
  }
  candidates.sort(function (a, b) { return a.fr.y - b.fr.y; });
  return candidates[0] || null;
}

function textMentionsUK(rows) {
  for (var i = 0; i < rows.length; i++) {
    var b = (rows[i].bits || '').toLowerCase();
    if (b.indexOf('+44') >= 0 || b.indexOf('united kingdom') >= 0 || b.indexOf('ingiltere') >= 0) return true;
  }
  return false;
}

ObjC.schedule(ObjC.mainQueue, function () {
  console.log('[+] fix_country_signup want +' + WANT_CC + ' / ' + NATIONAL);
  var rows = dump('start');

  // 1) tap country selector (left of phone field)
  var cc = findCountryHit(rows);
  if (cc && cc.fr) {
    var cx = cc.fr.x + cc.fr.w / 2;
    var cy = cc.fr.y + cc.fr.h / 2;
    // account for scroll hosting offset? frames from description are window-ish
    // earlier phone screen had scroll at y=85; hit frames were relative to scroll content
    // Use absolute from dump: country was (23.5 158.5) inside scroll starting 85 => window ~ (80, 243)?
    // But hitTest uses window coords. Convert: if fr is in superview, use convertPoint.
    try {
      var win = keyWindow();
      var pt = cc.v.convertPoint_toView_([cc.fr.w / 2, cc.fr.h / 2], win);
      // convertPoint may need [x,y]
      console.log('[CC] convert got ' + pt);
    } catch (e) {
      console.log('[CC] convert err ' + e);
    }
    // Prefer convert using NativeFunction / array
    var absX = cx, absY = cy;
    try {
      // UIView convertPoint:toView: with [x,y] local center
      var p = cc.v.convertPoint_toView_([cc.fr.w / 2, cc.fr.h / 2], NULL);
      // return may be array-like
      if (p && p.length >= 2) { absX = p[0]; absY = p[1]; }
      else if (p && typeof p.x === 'number') { absX = p.x; absY = p.y; }
      console.log('[CC] abs via convert = ' + absX + ',' + absY);
    } catch (e) {
      // fallback: scroll offset 85 from earlier dump
      absX = cx;
      absY = cy + 85;
      console.log('[CC] fallback abs ' + absX + ',' + absY + ' err=' + e);
    }
    tapAt(absX, absY, 'country-picker');
  } else {
    console.log('[CC] no country hit ??? tapping approx (80, 244)');
    tapAt(80, 244, 'country-fallback');
  }

  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      var rows2 = dump('after-cc-tap');
      // try find search field and type United Kingdom / 44
      var search = null;
      for (var i = 0; i < rows2.length; i++) {
        if (rows2[i].cls === 'UITextField' || rows2[i].cls === 'UISearchBarTextField') {
          search = rows2[i].v;
          // prefer placeholder search-like
          var ph = rows2[i].bits || '';
          if (ph.toLowerCase().indexOf('search') >= 0 || ph.indexOf('ph=') >= 0) {
            search = rows2[i].v;
            break;
          }
        }
      }
      if (search) {
        console.log('[CC] typing into search/field');
        fillInsert(search, 'United Kingdom');
      } else {
        console.log('[CC] no search field visible yet');
      }
    });
  }, 1500);

  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      var rows3 = dump('after-search');
      // tap a row that mentions United Kingdom or +44
      var picked = false;
      for (var i = 0; i < rows3.length; i++) {
        var r = rows3[i];
        var b = (r.bits || '').toLowerCase();
        if (b.indexOf('united kingdom') >= 0 || b.indexOf('+44') >= 0 || b.indexOf('ingiltere') >= 0) {
          if (r.fr) {
            var x = r.fr.x + r.fr.w / 2;
            var y = r.fr.y + r.fr.h / 2;
            try {
              var p = r.v.convertPoint_toView_([r.fr.w / 2, r.fr.h / 2], NULL);
              if (p && p.length >= 2) { x = p[0]; y = p[1]; }
            } catch (e) {}
            tapAt(x, y, 'pick-UK');
            picked = true;
            break;
          } else {
            try {
              if (r.v.respondsToSelector_(ObjC.selector('accessibilityActivate'))) {
                r.v.accessibilityActivate();
                console.log('[CC] a11y activate on UK row');
                picked = true;
                break;
              }
            } catch (e) {}
          }
        }
      }
      if (!picked) {
        // try HitTesting cells in list area
        for (var j = 0; j < rows3.length; j++) {
          var h = rows3[j];
          if (!h.fr || h.cls.indexOf('HitTesting') < 0) continue;
          if (h.fr.y > 100 && h.fr.y < 400 && h.fr.w > 200) {
            var hx = h.fr.x + h.fr.w / 2;
            var hy = h.fr.y + h.fr.h / 2;
            tapAt(hx, hy, 'pick-first-list-row');
            picked = true;
            break;
          }
        }
      }
      if (!picked) console.log('[CC] could not find UK row ??? dump above');
    });
  }, 3500);

  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      var rows4 = dump('after-pick');
      var tf = findPhoneField(rows4);
      if (tf) fillInsert(tf, NATIONAL);
      else console.log('[FILL] no phone field');
    });
  }, 5500);

  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      var rows5 = dump('before-signup');
      console.log('[CHK] ukVisible=' + textMentionsUK(rows5));
      var su = findSignUpHit(rows5);
      if (su && su.fr) {
        var x = su.fr.x + su.fr.w / 2;
        var y = su.fr.y + su.fr.h / 2;
        try {
          var p = su.v.convertPoint_toView_([su.fr.w / 2, su.fr.h / 2], NULL);
          if (p && p.length >= 2) { x = p[0]; y = p[1]; }
        } catch (e) {}
        tapAt(x, y, 'SignUp');
      } else {
        // screenshot: Sign Up roughly mid screen above keyboard ??? try (207, 320)
        console.log('[SU] fallback tap');
        tapAt(207, 320, 'SignUp-fallback');
      }
    });
  }, 7500);

  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      dump('final');
    });
  }, 10000);
});
