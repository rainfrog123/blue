// Probe tap methods for SwiftUI Register button
// frida -H 192.168.31.167 -n Kliq -l probe_tap.js -q -t 45

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

function findRegister(root) {
  var found = [];
  function walk(v, d) {
    if (!v || d > 20) return;
    var cls = v.$className || '';
    if (cls.indexOf('HitTesting') >= 0) {
      var fr = parseFrame(v.description().toString());
      if (fr && fr.y > 580 && fr.x > 180) found.push({ v: v, fr: fr, cls: cls });
    }
    try {
      var s = v.subviews();
      for (var i = 0; i < s.count(); i++) walk(s.objectAtIndex_(i), d + 1);
    } catch (e) {}
  }
  walk(root, 0);
  found.sort(function (a, b) { return b.fr.x - a.fr.x; });
  return found[0] || null;
}

function tryFormats(win, x, y) {
  var formats = [
    ['obj', { x: x, y: y }],
    ['arr2', [x, y]],
    ['arr4', [x, y, 0, 0]]
  ];
  for (var i = 0; i < formats.length; i++) {
    var name = formats[i][0];
    var pt = formats[i][1];
    try {
      var hit = win.hitTest_withEvent_(pt, NULL);
      console.log('[FMT] ' + name + ' OK hit=' + (hit ? hit.$className : 'null'));
    } catch (e) {
      console.log('[FMT] ' + name + ' FAIL ' + e);
    }
  }

  // NativeFunction with CGPoint by value (two doubles)
  try {
    var sel = ObjC.selector('hitTest:withEvent:');
    var impl = win.hitTest_withEvent_.implementation;
    var nf = new NativeFunction(impl, 'pointer', ['pointer', 'pointer', 'double', 'double', 'pointer']);
    var hit2 = new ObjC.Object(nf(win.handle, sel, x, y, NULL));
    console.log('[FMT] native doubles OK hit=' + hit2.$className);
    return hit2;
  } catch (e) {
    console.log('[FMT] native doubles FAIL ' + e);
  }
  return null;
}

function activateChain(view) {
  var cur = view;
  for (var i = 0; i < 8 && cur && !cur.isNull(); i++) {
    try {
      console.log('[A11Y] try ' + i + ' ' + cur.$className);
      if (cur.respondsToSelector_(ObjC.selector('accessibilityActivate'))) {
        var ok = cur.accessibilityActivate();
        console.log('[A11Y] activate=' + ok + ' traits=' + (cur.respondsToSelector_(ObjC.selector('accessibilityTraits')) ? cur.accessibilityTraits() : '?'));
      }
      if (cur.respondsToSelector_(ObjC.selector('sendActionsForControlEvents:'))) {
        cur.sendActionsForControlEvents_(64);
        console.log('[A11Y] sendActions');
      }
      // UIControl-like
      if (cur.respondsToSelector_(ObjC.selector('endTrackingWithTouch:withEvent:'))) {
        console.log('[A11Y] has endTracking');
      }
    } catch (e) {
      console.log('[A11Y] err ' + e);
    }
    try { cur = cur.superview(); } catch (e) { break; }
  }
}

function gestureFire(view) {
  try {
    var gens = view.gestureRecognizers();
    if (!gens) {
      console.log('[GES] no gens on ' + view.$className);
      return;
    }
    console.log('[GES] count=' + gens.count());
    for (var i = 0; i < gens.count(); i++) {
      var g = gens.objectAtIndex_(i);
      console.log('[GES] ' + g.$className + ' enabled=' + g.isEnabled() + ' state=' + g.state());
      try {
        // private: _setState: / setState
        if (g.respondsToSelector_(ObjC.selector('touchesBegan:withEvent:'))) {
          console.log('[GES] has touchesBegan');
        }
      } catch (e) {}
    }
  } catch (e) {
    console.log('[GES] err ' + e);
  }
}

function tapViaTouch(win, view, x, y) {
  // Build CGPoint via NSValue
  try {
    var NSValue = ObjC.classes.NSValue;
    var val = null;
    try {
      val = NSValue.valueWithCGPoint_({ x: x, y: y });
      console.log('[NSV] valueWithCGPoint obj OK ' + val);
    } catch (e) {
      console.log('[NSV] obj FAIL ' + e);
    }
    try {
      val = NSValue.valueWithCGPoint_([x, y]);
      console.log('[NSV] valueWithCGPoint arr OK ' + val);
    } catch (e) {
      console.log('[NSV] arr FAIL ' + e);
    }
  } catch (e) {}

  // UITouch initAtPoint:inView: / initAtPoint:inWindow: (private)
  var UITouch = ObjC.classes.UITouch;
  var methods = UITouch.$ownMethods.filter(function (m) {
    return m.toLowerCase().indexOf('init') >= 0 || m.toLowerCase().indexOf('point') >= 0 || m.toLowerCase().indexOf('location') >= 0;
  });
  console.log('[TOUCH methods] ' + methods.slice(0, 40).join(' | '));

  try {
    if (UITouch['- initWithPoint:inWindow:']) {
      console.log('[TOUCH] has initWithPoint:inWindow:');
    }
  } catch (e) {}
}

ObjC.schedule(ObjC.mainQueue, function () {
  var vc = topVC();
  console.log('[TOP] ' + (vc ? vc.$className : 'null'));
  var win = ObjC.classes.UIApplication.sharedApplication().keyWindow();
  var reg = findRegister(vc.view());
  if (!reg) {
    console.log('[!] no register hit view');
    return;
  }
  var cx = reg.fr.x + reg.fr.w / 2;
  var cy = reg.fr.y + reg.fr.h / 2;
  console.log('[REG] ' + reg.cls + ' center=' + cx + ',' + cy);

  var hit = tryFormats(win, cx, cy);
  activateChain(reg.v);
  gestureFire(reg.v);
  tapViaTouch(win, reg.v, cx, cy);

  // Also try: performSelector tap via UIControl
  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      var vc2 = topVC();
      console.log('[AFTER] TOP=' + (vc2 ? vc2.$className : 'null'));
    });
  }, 2000);
});
