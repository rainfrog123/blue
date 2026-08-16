// frida -U -f com.hxgy.hxgyapp -l bypass-update.js -q -t inf
// Do not add HytUpdateAlertView. Hide is a no-op on this card (still painted).

function cls(o) {
  try { return o ? o.$className : 'null'; } catch (e) { return '?'; }
}

function txt(v) {
  var s = '';
  try { if (v.text && v.text()) s += v.text().toString(); } catch (e) {}
  try { if (v.currentTitle && v.currentTitle()) s += v.currentTitle().toString(); } catch (e) {}
  try {
    if (v.attributedText && v.attributedText()) s += v.attributedText().string().toString();
  } catch (e) {}
  return s;
}

function frameStr(v) {
  try {
    var f = v.frame();
    return f.origin.x.toFixed(0) + ',' + f.origin.y.toFixed(0) + ' ' + f.size.width.toFixed(0) + 'x' + f.size.height.toFixed(0);
  } catch (e) {
    return '?';
  }
}

function hideTree(v, tag) {
  if (!v) return;
  try { v.setHidden_(1); } catch (e) {}
  try { v.setAlpha_(0); } catch (e) {}
  try { v.setUserInteractionEnabled_(0); } catch (e) {}
  console.log(tag + ' ' + cls(v) + ' ' + frameStr(v));
}

function coverFromLabel(v) {
  var cur = v;
  var best = v;
  for (var i = 0; i < 14 && cur; i++) {
    try {
      var f = cur.frame();
      if (f.size.width >= 300 && f.size.height >= 400) best = cur;
    } catch (e) {}
    try { cur = cur.superview(); } catch (e) { break; }
  }
  return best;
}

function walkHideHits(view) {
  if (!view) return;
  var t = txt(view);
  if (t.indexOf('发现新版本') >= 0 || t.indexOf('立即升级') >= 0) {
    hideTree(coverFromLabel(view), '[hit-cover]');
    hideTree(view, '[hit-label]');
  }
  try {
    var subs = view.subviews();
    for (var i = 0; i < subs.count(); i++) walkHideHits(subs.objectAtIndex_(i));
  } catch (e) {}
}

function dumpShallow(tag) {
  var app = ObjC.classes.UIApplication.sharedApplication();
  if (!app || !app.windows()) return;
  var wins = app.windows();
  console.log(tag + ' windows=' + wins.count());
  for (var i = 0; i < wins.count(); i++) {
    var w = wins.objectAtIndex_(i);
    console.log(tag + ' win' + i + ' ' + cls(w) + ' hid=' + w.isHidden() + ' ' + frameStr(w));
    walkDump(w, 0, tag);
    walkHideHits(w);
  }
}

function walkDump(view, depth, tag) {
  if (!view || depth > 8) return;
  var t = txt(view);
  var name = cls(view);
  if (t || /Update|Alert|Guide|Image|Window/i.test(name) || depth <= 2) {
    var hid = '?';
    try { hid = view.isHidden(); } catch (e) {}
    console.log(tag + ' ' + Array(depth + 1).join('  ') + name + ' hid=' + hid + ' ' + frameStr(view) + (t ? '  ' + t.replace(/\n/g, ' | ') : ''));
  }
  try {
    var subs = view.subviews();
    for (var i = 0; i < subs.count(); i++) walkDump(subs.objectAtIndex_(i), depth + 1, tag);
  } catch (e) {}
}

function skipIfAlert(impl) {
  Interceptor.attach(impl, {
    onEnter: function (args) {
      try {
        var sub = new ObjC.Object(args[2]);
        if (sub.$className === 'HytUpdateAlertView') {
          this.skip = true;
          args[2] = ObjC.classes.UIView.alloc().init();
          console.log('[skip] replaced alert add with dummy UIView');
        }
      } catch (e) {}
    }
  });
}

if (!ObjC.available) {
  console.log('no objc');
} else {
  var C = ObjC.classes.HytUpdateAlertView;
  var UIView = ObjC.classes.UIView;

  Interceptor.attach(C['- must'].implementation, {
    onLeave: function (retval) { retval.replace(ptr(0)); }
  });
  Interceptor.attach(C['- setMust:'].implementation, {
    onEnter: function (args) { args[2] = ptr(0); }
  });

  Interceptor.attach(C['+ alertWithText:must:resp:'].implementation, {
    onEnter: function (args) {
      var text = '';
      try { text = new ObjC.Object(args[2]).toString(); } catch (e) {}
      console.log('[alert] must_in=' + args[3] + ' ' + text.replace(/\n/g, ' | '));
      args[3] = ptr(0);
    },
    onLeave: function (retval) {
      setTimeout(function () { dumpShallow('[+0.8s]'); }, 800);
      setTimeout(function () { dumpShallow('[+2s]'); }, 2000);
    }
  });

  skipIfAlert(UIView['- addSubview:'].implementation);
  if (UIView['- insertSubview:atIndex:']) skipIfAlert(UIView['- insertSubview:atIndex:'].implementation);
  if (UIView['- insertSubview:aboveSubview:']) skipIfAlert(UIView['- insertSubview:aboveSubview:'].implementation);
  if (UIView['- insertSubview:belowSubview:']) skipIfAlert(UIView['- insertSubview:belowSubview:'].implementation);

  console.log('bypass: skip add HytUpdateAlertView + dump');
}
