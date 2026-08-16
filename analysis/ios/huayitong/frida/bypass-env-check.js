// Skip the 运行环境异常 / 强制退出 UIAlertController on 华医通.
// Analog of bypass-update.js (skip-add) but for presentViewController: (skip-present).
// frida -U -f com.hxgy.hxgyapp -l bypass-env-check.js -q -t inf
//
// What it does:
//   1. Swizzle -[UIViewController presentViewController:animated:completion:] and drop
//      any UIAlertController whose title/message matches the env-check warning. Logs a
//      backtrace so you can find the detection call site in the binary.
//   2. Hooks exit/abort/_Exit and the private UIApplication terminate selectors as a
//      safety net in case the app forces quit without going through the 退出 button.
//   3. Scans ObjC classes for env-check-looking names once at startup.
//
// Trigger not isolated yet (Frida + Shadowrocket + RootHide all present). See the
// run matrix in Bypass Huayitong Env Check before trusting this.

var KEYS = ['运行环境异常', '强制退出', '警告'];
var seen = {};

function isEnvAlert(vc) {
  if (!vc || vc.isNull()) return false;
  try {
    if (vc.$className !== 'UIAlertController') return false;
  } catch (e) { return false; }
  var title = '', msg = '';
  try { if (vc.title()) title = vc.title().toString(); } catch (e) {}
  try { if (vc.message()) msg = vc.message().toString(); } catch (e) {}
  for (var i = 0; i < KEYS.length; i++) {
    if (title.indexOf(KEYS[i]) >= 0 || msg.indexOf(KEYS[i]) >= 0) return true;
  }
  return false;
}

function logAlert(vc, tag) {
  var title = '', msg = '';
  try { if (vc.title()) title = vc.title().toString(); } catch (e) {}
  try { if (vc.message()) msg = vc.message().toString(); } catch (e) {}
  console.log(tag + ' alert ' + vc.$className + ' title=' + title + ' msg=' + msg);
  try {
    var acts = vc.actions();
    for (var i = 0; i < acts.count(); i++) {
      var a = acts.objectAtIndex_(i);
      console.log(tag + '   action[' + i + '] ' + a.title() + ' style=' + a.style());
    }
  } catch (e) {}
}

function scanClasses() {
  var hits = [];
  for (var name in ObjC.classes) {
    if (/Env|Security|Safe|Jail|Root|Debug|Detect|Check|Risk|Hook|Inject|Frida|Cydia|Substrate/i.test(name)) {
      if (/HX|HYT|hxgy|Hyt|华医/.test(name) || /Env|Security|Safe|Jail|Root|Debug|Detect|Risk|Hook|Inject/.test(name)) {
        hits.push(name);
      }
    }
  }
  hits.sort();
  console.log('[classes] ' + hits.length + ' candidates:\n  ' + hits.join('\n  '));
}

if (!ObjC.available) {
  console.log('no objc');
} else {
  // --- 1. skip-present -----------------------------------------------------
  var m = ObjC.classes.UIViewController['- presentViewController:animated:completion:'];
  var origImpl = m.implementation;
  var msgSend = new NativeFunction(
    ObjC.api.objc_msgSend, 'void', ['pointer', 'pointer', 'pointer', 'uint8', 'pointer']
  );

  m.implementation = ObjC.implement(m, function (self, sel, vc, anim, comp) {
    if (isEnvAlert(vc)) {
      logAlert(vc, '[skip-present]');
      try {
        console.log('[skip-present] backtrace:\n' +
          Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
      } catch (e) { console.log('[skip-present] bt fail ' + e); }
      // call completion (if any) so the caller proceeds, then return without presenting
      try {
        if (comp && !comp.isNull()) {
          var block = new ObjC.Block(comp);
          block();
        }
      } catch (e) { console.log('[skip-present] comp fail ' + e); }
      return;
    }
    // pass everything else through to the original IMP
    msgSend(self, sel, vc, anim ? 1 : 0, comp);
  });
  console.log('[skip-present] swizzle installed on UIViewController');

  // --- 2. exit / abort safety net ------------------------------------------
  function blockExit(name, sig) {
    var p = Module.findExportByName(null, name);
    if (!p) return;
    Interceptor.replace(p, new NativeCallback(function () {
      console.log('[blocked] ' + name + ' called');
      try {
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
          .map(DebugSymbol.fromAddress).join('\n'));
      } catch (e) {}
    }, 'void', sig));
    console.log('[blocked] ' + name + ' hooked');
  }
  blockExit('exit', ['int']);
  blockExit('_Exit', ['int']);
  blockExit('abort', []);
  blockExit('exit_thread', []);

  // private UIApplication terminate selectors (iOS)
  ['_terminateWithSuccess', 'terminateWithSuccess', '_terminateWithStatus:'].forEach(function (sel) {
    var C = ObjC.classes.UIApplication;
    if (C['- ' + sel]) {
      Interceptor.attach(C['- ' + sel].implementation, {
        onEnter: function () {
          console.log('[blocked] UIApplication ' + sel);
          try {
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
              .map(DebugSymbol.fromAddress).join('\n'));
          } catch (e) {}
        }
      });
      console.log('[blocked] UIApplication ' + sel + ' hooked');
    }
  });

  // --- 3. class scan -------------------------------------------------------
  setTimeout(scanClasses, 2500);

  console.log('bypass-env-check ready (skip-present + exit net + class scan)');
}
