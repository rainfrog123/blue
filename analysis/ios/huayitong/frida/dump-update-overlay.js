// Attach to running Huayitong and find the 发现新版本 overlay.
// frida -U -N com.hxgy.hxgyapp -l dump-update-overlay.js -q -t 8

var KEYS = ['发现新版本', '立即升级', '新版本', '升级', 'NEW', 'wifi', 'WiFi', 'Wi-Fi'];

function cls(o) {
  try { return o ? o.$className : 'null'; } catch (e) { return '?'; }
}

function textOf(v) {
  var bits = [];
  try { if (v.text && v.text()) bits.push('text=' + v.text().toString()); } catch (e) {}
  try { if (v.currentTitle && v.currentTitle()) bits.push('title=' + v.currentTitle().toString()); } catch (e) {}
  try { if (v.attributedText && v.attributedText()) bits.push('attr=' + v.attributedText().string().toString().slice(0, 80)); } catch (e) {}
  try {
    if (v.placeholder && v.placeholder()) bits.push('ph=' + v.placeholder().toString());
  } catch (e) {}
  return bits.join(' ');
}

function hitsKey(s) {
  if (!s) return false;
  for (var i = 0; i < KEYS.length; i++) if (s.indexOf(KEYS[i]) >= 0) return true;
  return false;
}

function walk(view, depth, acc) {
  if (!view || depth > 18) return;
  var name = cls(view);
  var extra = textOf(view);
  var interesting =
    hitsKey(name) || hitsKey(extra) ||
    /Update|Version|Guide|Alert|Popup|Dialog|Mask|Cover|HUD|Tip/i.test(name);
  acc.push({
    depth: depth,
    view: view,
    name: name,
    extra: extra,
    interesting: interesting
  });
  try {
    var subs = view.subviews();
    for (var i = 0; i < subs.count(); i++) walk(subs.objectAtIndex_(i), depth + 1, acc);
  } catch (e) {}
}

function dumpClasses() {
  var hits = [];
  for (var name in ObjC.classes) {
    if (/Update|Version|Guide|Alert|Popup|Upgrade|Force/i.test(name) && /HX|HYT|hxgy|华医/i.test(name)) {
      hits.push(name);
    } else if (/HX.*Update|HX.*Version|HX.*Guide|HX.*Alert|HX.*Popup/i.test(name)) {
      hits.push(name);
    }
  }
  hits.sort();
  console.log('class hits (' + hits.length + '): ' + hits.join(', '));
}

function run() {
  dumpClasses();
  var app = ObjC.classes.UIApplication.sharedApplication();
  var wins = app.windows();
  var key = app.keyWindow();
  console.log('windows=' + wins.count() + ' key=' + cls(key));
  var found = [];
  for (var i = 0; i < wins.count(); i++) {
    var w = wins.objectAtIndex_(i);
    var acc = [];
    walk(w, 0, acc);
    console.log('--- window ' + i + ' ' + cls(w) + (w.isEqual_(key) ? ' KEY' : '') + ' views=' + acc.length);
    acc.forEach(function (n) {
      if (n.interesting || n.extra) {
        var line = Array(n.depth + 1).join('  ') + n.name + (n.extra ? '  ' + n.extra : '');
        console.log(line);
        if (hitsKey(n.extra) || hitsKey(n.name)) found.push(n);
      }
    });
  }
  console.log('text hits=' + found.length);
  found.forEach(function (n) {
    console.log('HIT ' + n.name + ' ' + n.extra);
  });
}

if (ObjC.available) {
  run();
} else {
  console.log('no objc');
}
