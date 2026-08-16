// Spawn Huayitong, wait for 发现新版本, dump it, then remove the overlay.
// frida -U -f com.hxgy.hxgyapp -l dismiss-update.js -q -t 30

var KEYS = ['发现新版本', '立即升级', '建议在wifi', '建议在Wi'];
var dismissed = false;
var seen = {};

function cls(o) {
  try { return o ? o.$className : 'null'; } catch (e) { return '?'; }
}

function textOf(v) {
  var bits = [];
  try { if (v.text && v.text()) bits.push(v.text().toString()); } catch (e) {}
  try { if (v.currentTitle && v.currentTitle()) bits.push(v.currentTitle().toString()); } catch (e) {}
  try {
    if (v.attributedText && v.attributedText()) bits.push(v.attributedText().string().toString());
  } catch (e) {}
  return bits.join(' | ');
}

function hits(s) {
  if (!s) return false;
  for (var i = 0; i < KEYS.length; i++) if (s.indexOf(KEYS[i]) >= 0) return true;
  return false;
}

function walk(view, depth, acc) {
  if (!view || depth > 20) return;
  acc.push({ depth: depth, view: view, name: cls(view), extra: textOf(view) });
  try {
    var subs = view.subviews();
    for (var i = 0; i < subs.count(); i++) walk(subs.objectAtIndex_(i), depth + 1, acc);
  } catch (e) {}
}

function overlayRoot(view) {
  var cur = view;
  var best = view;
  for (var i = 0; i < 16 && cur; i++) {
    var name = cls(cur);
    if (name === 'UIWindow' || name === 'UITransitionView') break;
    if (/Guide|Update|Alert|Popup|Mask|Cover|Dialog|Tip|HUD|Version/i.test(name)) best = cur;
    if (name.indexOf('HX') === 0 || name.indexOf('HYT') === 0) best = cur;
    try { cur = cur.superview(); } catch (e) { break; }
  }
  return best;
}

function dumpClasses() {
  var hitsList = [];
  for (var name in ObjC.classes) {
    if (/Update|Version|Guide|Upgrade|Force/i.test(name)) hitsList.push(name);
  }
  hitsList.sort();
  console.log('classes: ' + hitsList.join(', '));
}

function tryDismiss(fromView) {
  if (dismissed) return;
  var root = overlayRoot(fromView);
  console.log('dismiss target=' + cls(root) + ' super=' + cls(root.superview()));
  try {
    root.removeFromSuperview();
    console.log('removed ' + cls(root));
    dismissed = true;
  } catch (e) {
    console.log('remove fail ' + e);
  }
  try {
    root.setHidden_(true);
    console.log('hidden ' + cls(root));
  } catch (e) {}
  try {
    root.setUserInteractionEnabled_(false);
  } catch (e) {}
}

function scan(tag) {
  var app = ObjC.classes.UIApplication.sharedApplication();
  if (!app) {
    console.log(tag + ' no app');
    return;
  }
  var wins = app.windows();
  if (!wins) return;
  for (var i = 0; i < wins.count(); i++) {
    var acc = [];
    walk(wins.objectAtIndex_(i), 0, acc);
    acc.forEach(function (n) {
      if (!n.extra && !/Guide|Update|Alert|Popup|Mask|Cover|Dialog|Version/i.test(n.name)) return;
      var key = n.name + '|' + n.extra;
      if (!seen[key] && (n.extra || n.depth <= 4)) {
        seen[key] = 1;
        if (n.extra || /Guide|Update|Alert|Popup|Mask|Cover|Dialog|Version/i.test(n.name)) {
          console.log(tag + ' ' + Array(n.depth + 1).join('  ') + n.name + (n.extra ? '  ' + n.extra : ''));
        }
      }
      if (hits(n.extra) || hits(n.name)) {
        console.log(tag + ' HIT ' + n.name + ' ' + n.extra);
        tryDismiss(n.view);
      }
    });
  }
}

if (!ObjC.available) {
  console.log('no objc');
} else {
  ['UILabel', 'UIButton'].forEach(function (cn) {
    var C = ObjC.classes[cn];
    if (!C) return;
    if (C['- setText:']) {
      Interceptor.attach(C['- setText:'].implementation, {
        onEnter: function (args) {
          var t = new ObjC.Object(args[2]).toString();
          if (hits(t)) {
            console.log('[setText] ' + cn + ' ' + t);
            var v = new ObjC.Object(args[0]);
            setTimeout(function () { tryDismiss(v); }, 50);
          }
        }
      });
    }
    if (C['- setTitle:forState:']) {
      Interceptor.attach(C['- setTitle:forState:'].implementation, {
        onEnter: function (args) {
          var t = new ObjC.Object(args[2]).toString();
          if (hits(t)) {
            console.log('[setTitle] ' + cn + ' ' + t);
            var v = new ObjC.Object(args[0]);
            setTimeout(function () { tryDismiss(v); }, 50);
          }
        }
      });
    }
  });
  setTimeout(function () { dumpClasses(); }, 1500);
  var t = 0;
  var iv = setInterval(function () {
    t += 500;
    scan('+' + t + 'ms');
    if (t >= 25000) clearInterval(iv);
  }, 500);
  console.log('watching for update overlay');
}
