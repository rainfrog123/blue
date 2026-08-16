// Spawn Huayitong and dump first UIWindow + VC chain.
// frida -U -f com.hxgy.hxgyapp -l dump-first-window.js -q -t 12

function cls(o) {
  try { return o ? o.$className : 'null'; } catch (e) { return '?' + e; }
}

function topVC(vc) {
  var guard = 0;
  while (vc && guard++ < 20) {
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
  return vc;
}

function vcChain(vc) {
  var parts = [];
  var guard = 0;
  while (vc && guard++ < 20) {
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

function dumpViews(view, depth, maxDepth, lines) {
  if (!view || depth > maxDepth) return;
  var indent = Array(depth + 1).join('  ');
  var extra = '';
  try {
    if (view.isKindOfClass_(ObjC.classes.UILabel) && view.text()) extra = ' text=' + view.text().toString();
  } catch (e) {}
  try {
    if (view.isKindOfClass_(ObjC.classes.UIButton) && view.currentTitle()) extra = ' title=' + view.currentTitle().toString();
  } catch (e) {}
  lines.push(indent + cls(view) + extra);
  try {
    var subs = view.subviews();
    for (var i = 0; i < subs.count(); i++) dumpViews(subs.objectAtIndex_(i), depth + 1, maxDepth, lines);
  } catch (e) {}
}

function dumpOnce(tag) {
  console.log('========== ' + tag + ' ==========');
  var app = null;
  try { app = ObjC.classes.UIApplication.sharedApplication(); } catch (e) {}
  if (!app) {
    console.log('UIApplication still null');
    return;
  }
  var wins = null;
  try { wins = app.windows(); } catch (e) {}
  var key = null;
  try { key = app.keyWindow(); } catch (e) {}
  console.log('windows=' + (wins ? wins.count() : 0) + ' keyWindow=' + cls(key));
  if (!wins) return;
  for (var i = 0; i < wins.count(); i++) {
    var w = wins.objectAtIndex_(i);
    var isKey = key && w.isEqual_(key);
    var hidden = false;
    try { hidden = w.isHidden(); } catch (e) {}
    var level = '?';
    try { level = w.windowLevel().toString(); } catch (e) {}
    var root = null;
    try { root = w.rootViewController(); } catch (e) {}
    console.log(
      '[' + i + '] ' + cls(w) +
      (isKey ? '  KEY' : '') +
      ' hidden=' + hidden +
      ' level=' + level +
      ' root=' + cls(root)
    );
    if (root) {
      console.log('    chain: ' + vcChain(root));
      console.log('    top:   ' + cls(topVC(root)));
    }
    if (isKey || i === 0) {
      var lines = [];
      try { dumpViews(w, 0, 3, lines); } catch (e) { lines.push('view dump fail ' + e); }
      console.log(lines.join('\n'));
    }
  }
}

if (!ObjC.available) {
  console.log('ObjC not available');
} else {
  Interceptor.attach(ObjC.classes.UIWindow['- makeKeyAndVisible'].implementation, {
    onEnter: function (args) {
      this.win = new ObjC.Object(args[0]);
    },
    onLeave: function () {
      var root = null;
      try { root = this.win.rootViewController(); } catch (e) {}
      console.log('[hook] makeKeyAndVisible ' + cls(this.win) + ' root=' + cls(root));
      if (root) console.log('[hook] chain: ' + vcChain(root));
      dumpOnce('makeKeyAndVisible');
    }
  });
  console.log('hooks ready; waiting for UI');
  [200, 500, 1000, 2000, 4000, 8000].forEach(function (ms) {
    setTimeout(function () { dumpOnce('+' + ms + 'ms'); }, ms);
  });
}
