// frida -U -f com.hxgy.hxgyapp -l inspect-update-alert.js -q -t 20

function methodsOf(name) {
  var C = ObjC.classes[name];
  if (!C) {
    console.log(name + ' missing');
    return;
  }
  var own = C.$ownMethods;
  console.log('=== ' + name + ' own=' + own.length + ' ===');
  own.forEach(function (m) { console.log('  ' + m); });
}

function hideAlert(tag) {
  var C = ObjC.classes.HytUpdateAlertView;
  if (!C) return;
  var app = ObjC.classes.UIApplication.sharedApplication();
  if (!app || !app.windows()) return;
  var wins = app.windows();
  for (var i = 0; i < wins.count(); i++) {
    hideWalk(wins.objectAtIndex_(i), tag);
  }
}

function hideWalk(view, tag) {
  if (!view) return;
  try {
    if (view.isKindOfClass_(ObjC.classes.HytUpdateAlertView)) {
      console.log(tag + ' hide ' + view.$className);
      try { view.setHidden_(true); } catch (e) { console.log('hidden fail ' + e); }
      try { view.setAlpha_(0); } catch (e) {}
      try { view.setUserInteractionEnabled_(false); } catch (e) {}
      try {
        var close = view.closeButton ? view.closeButton() : null;
        if (close) console.log('closeButton=' + close.$className);
      } catch (e) {}
    }
  } catch (e) {}
  try {
    var subs = view.subviews();
    for (var i = 0; i < subs.count(); i++) hideWalk(subs.objectAtIndex_(i), tag);
  } catch (e) {}
}

if (!ObjC.available) {
  console.log('no objc');
} else {
  setTimeout(function () {
    ['HytUpdateAlertView', 'HXGuideView'].forEach(methodsOf);
    var extra = [];
    for (var n in ObjC.classes) {
      if (/Hyt.*Update|Hyt.*Version|HX.*Update|HX.*Version/i.test(n)) extra.push(n);
    }
    console.log('related: ' + extra.join(', '));
  }, 2500);
  setTimeout(function () { hideAlert('+3s'); }, 3000);
  setTimeout(function () { hideAlert('+5s'); }, 5000);
  setTimeout(function () { hideAlert('+8s'); }, 8000);
  console.log('will inspect + hide HytUpdateAlertView');
}
