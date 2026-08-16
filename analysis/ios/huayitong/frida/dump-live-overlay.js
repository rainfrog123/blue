// Attach to running app: frida -U -n 华医通 -l dump-live-overlay.js -q -t 6

function cls(o) {
  try { return o ? o.$className : 'null'; } catch (e) { return '?'; }
}

function txt(v) {
  var s = '';
  try { if (v.text && v.text()) s += v.text().toString(); } catch (e) {}
  try { if (v.currentTitle && v.currentTitle()) s += '|' + v.currentTitle().toString(); } catch (e) {}
  try {
    if (v.attributedText && v.attributedText()) s += '|' + v.attributedText().string().toString().slice(0, 60);
  } catch (e) {}
  return s.replace(/\n/g, ' ');
}

function frame(v) {
  try {
    var f = v.frame();
    return f.origin.x.toFixed(0) + ',' + f.origin.y.toFixed(0) + ' ' + f.size.width.toFixed(0) + 'x' + f.size.height.toFixed(0);
  } catch (e) {
    return '?';
  }
}

function walk(view, depth, lines) {
  if (!view || depth > 16) return;
  var name = cls(view);
  var extra = txt(view);
  var hid = '?';
  var a = '?';
  try { hid = view.isHidden(); } catch (e) {}
  try { a = Number(view.alpha()).toFixed(2); } catch (e) {}
  var interesting = extra || /Update|Alert|Guide|Mask|Cover|Window|Image/i.test(name) || depth <= 3;
  if (interesting) {
    lines.push(Array(depth + 1).join('  ') + name + ' hid=' + hid + ' a=' + a + ' ' + frame(view) + (extra ? '  ' + extra : ''));
  }
  try {
    var subs = view.subviews();
    for (var i = 0; i < subs.count(); i++) walk(subs.objectAtIndex_(i), depth + 1, lines);
  } catch (e) {}
}

if (!ObjC.available) {
  console.log('no objc');
} else {
  var app = ObjC.classes.UIApplication.sharedApplication();
  var wins = app.windows();
  var key = app.keyWindow();
  console.log('windows=' + wins.count() + ' key=' + cls(key));
  for (var i = 0; i < wins.count(); i++) {
    var w = wins.objectAtIndex_(i);
    console.log('==== win ' + i + ' ' + cls(w) + (w.isEqual_(key) ? ' KEY' : '') + ' level=' + w.windowLevel() + ' hid=' + w.isHidden());
    var lines = [];
    walk(w, 0, lines);
    console.log(lines.join('\n'));
  }
  try {
    var alerts = ObjC.chooseSync(ObjC.classes.HytUpdateAlertView);
    console.log('choose HytUpdateAlertView count=' + alerts.length);
    alerts.forEach(function (v, n) {
      console.log('  #' + n + ' hid=' + v.isHidden() + ' a=' + v.alpha() + ' super=' + cls(v.superview()) + ' ' + frame(v));
    });
  } catch (e) {
    console.log('choose fail ' + e);
  }
}
