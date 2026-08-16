// Attach to running app: frida -U -n 华医通 -l dump-window.js -q -t 8
// Read-only window / VC / view dump. Does not hide, dismiss, or replace views.

function cls(o) {
  try { return o ? o.$className : 'null'; } catch (e) { return '?'; }
}

function txt(v) {
  var s = '';
  try { if (v.text && v.text()) s += ' text=' + v.text().toString().replace(/\n/g, ' '); } catch (e) {}
  try {
    if (v.currentTitle && v.currentTitle()) s += ' title=' + v.currentTitle().toString();
  } catch (e) {}
  try {
    if (v.attributedText && v.attributedText()) {
      s += ' attr=' + v.attributedText().string().toString().replace(/\n/g, ' ').slice(0, 80);
    }
  } catch (e) {}
  try {
    if (v.placeholder && v.placeholder()) s += ' ph=' + v.placeholder().toString();
  } catch (e) {}
  return s;
}

function frame(v) {
  try {
    var f = v.frame();
    return f.origin.x.toFixed(0) + ',' + f.origin.y.toFixed(0) + ' ' +
      f.size.width.toFixed(0) + 'x' + f.size.height.toFixed(0);
  } catch (e) {
    return '?';
  }
}

function walk(view, depth, lines) {
  if (!view || depth > 18) return;
  var hid = '?';
  var a = '?';
  try { hid = view.isHidden(); } catch (e) {}
  try { a = Number(view.alpha()).toFixed(2); } catch (e) {}
  lines.push(
    Array(depth + 1).join('  ') + cls(view) +
    ' hid=' + hid + ' a=' + a + ' ' + frame(view) + txt(view)
  );
  try {
    var subs = view.subviews();
    for (var i = 0; i < subs.count(); i++) walk(subs.objectAtIndex_(i), depth + 1, lines);
  } catch (e) {}
}

function vcChain(vc) {
  var parts = [];
  var guard = 0;
  while (vc && guard++ < 24) {
    parts.push(cls(vc));
    try {
      if (vc.presentedViewController()) { vc = vc.presentedViewController(); continue; }
    } catch (e) {}
    try {
      if (vc.isKindOfClass_(ObjC.classes.UINavigationController) && vc.visibleViewController()) {
        vc = vc.visibleViewController();
        continue;
      }
    } catch (e) {}
    try {
      if (vc.isKindOfClass_(ObjC.classes.UITabBarController) && vc.selectedViewController()) {
        vc = vc.selectedViewController();
        continue;
      }
    } catch (e) {}
    break;
  }
  return parts.join(' -> ');
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
    var root = null;
    try { root = w.rootViewController(); } catch (e) {}
    console.log(
      '==== win ' + i + ' ' + cls(w) +
      (w.isEqual_(key) ? ' KEY' : '') +
      ' level=' + w.windowLevel() +
      ' hid=' + w.isHidden() +
      ' root=' + cls(root)
    );
    if (root) console.log('chain: ' + vcChain(root));
    var lines = [];
    walk(w, 0, lines);
    console.log(lines.join('\n'));
  }
  try {
    var alerts = ObjC.chooseSync(ObjC.classes.UIAlertController);
    console.log('choose UIAlertController count=' + alerts.length);
    alerts.forEach(function (c, n) {
      var title = '';
      var msg = '';
      try { title = c.title() ? c.title().toString() : ''; } catch (e) {}
      try { msg = c.message() ? c.message().toString() : ''; } catch (e) {}
      console.log('  #' + n + ' title=' + title + ' msg=' + msg);
    });
  } catch (e) {
    console.log('choose UIAlertController fail ' + e);
  }
}
