// Probe UITouch/UIEvent private tap synthesis
// frida -H 192.168.31.167 -n Kliq -l probe_touch_event.js -q -t 40

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
      if (fr && fr.y > 580 && fr.x > 180) found.push({ v: v, fr: fr });
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

function hasSel(obj, name) {
  try {
    return obj.respondsToSelector_(ObjC.selector(name));
  } catch (e) {
    return false;
  }
}

function listInteresting(clsName) {
  var C = ObjC.classes[clsName];
  if (!C) {
    console.log('[?] missing ' + clsName);
    return;
  }
  var ms = C.$ownMethods.filter(function (m) {
    var l = m.toLowerCase();
    return (
      l.indexOf('touch') >= 0 ||
      l.indexOf('event') >= 0 ||
      l.indexOf('hid') >= 0 ||
      l.indexOf('send') >= 0 ||
      l.indexOf('phase') >= 0 ||
      l.indexOf('window') >= 0 ||
      l.indexOf('location') >= 0
    );
  });
  console.log('==== ' + clsName + ' (' + ms.length + ')');
  console.log(ms.slice(0, 60).join('\n'));
}

function synthesizeTap(x, y) {
  var app = ObjC.classes.UIApplication.sharedApplication();
  var win = app.keyWindow();
  var view = win.hitTest_withEvent_([x, y], NULL);
  console.log('[HIT] ' + (view ? view.$className : 'null'));

  var UITouch = ObjC.classes.UITouch;
  var touch = UITouch.alloc().init();
  console.log('[TOUCH] alloc init OK ' + touch);

  // set properties via respondsToSelector
  var steps = [
    ['setWindow:', function () { touch.setWindow_(win); }],
    ['setView:', function () { touch.setView_(view); }],
    ['setTapCount:', function () { touch.setTapCount_(1); }],
    ['setIsTap:', function () { touch.setIsTap_(1); }],
    ['setTimestamp:', function () { touch.setTimestamp_(ObjC.classes.NSProcessInfo.processInfo().systemUptime()); }],
    ['setPhase:', function () { touch.setPhase_(0); }],
    ['_setLocationInWindow:resetPrevious:', function () { touch['_setLocationInWindow:resetPrevious:']([x, y], 1); }],
    ['_setIsFirstTouchForView:', function () { touch['_setIsFirstTouchForView:'](1); }],
    ['setGestureView:', function () { touch.setGestureView_(view); }]
  ];
  for (var i = 0; i < steps.length; i++) {
    var name = steps[i][0];
    try {
      if (hasSel(touch, name)) {
        steps[i][1]();
        console.log('[SET] ' + name + ' OK');
      } else {
        console.log('[SET] ' + name + ' missing');
      }
    } catch (e) {
      console.log('[SET] ' + name + ' ERR ' + e);
    }
  }

  // Get UIEvent
  var event = null;
  var eventGetters = ['_touchesEvent', '_event', 'event'];
  for (var j = 0; j < eventGetters.length; j++) {
    try {
      if (hasSel(app, eventGetters[j])) {
        event = app[eventGetters[j]]();
        console.log('[EVT] app.' + eventGetters[j] + ' -> ' + event);
        if (event) break;
      } else {
        console.log('[EVT] app.' + eventGetters[j] + ' missing');
      }
    } catch (e) {
      console.log('[EVT] ' + eventGetters[j] + ' ERR ' + e);
    }
  }

  if (!event) {
    console.log('[EVT] trying UIEvent alloc');
    try {
      event = ObjC.classes.UIEvent.alloc().init();
      console.log('[EVT] alloc ' + event);
    } catch (e) {
      console.log('[EVT] alloc ERR ' + e);
    }
  }

  if (event) {
    var ems = [
      '_clearTouches',
      '_addTouch:forDelayedDelivery:',
      '_setHIDEvent:',
      'setTimestamp:'
    ];
    for (var k = 0; k < ems.length; k++) {
      console.log('[EVTSEL] ' + ems[k] + ' = ' + hasSel(event, ems[k]));
    }
    try {
      if (hasSel(event, '_clearTouches')) event._clearTouches();
      if (hasSel(event, '_addTouch:forDelayedDelivery:')) {
        event['_addTouch:forDelayedDelivery:'](touch, 0);
        console.log('[EVT] added touch began');
      }
      app.sendEvent_(event);
      console.log('[EVT] sendEvent began');

      touch.setPhase_(3); // ended
      if (hasSel(touch, '_setLocationInWindow:resetPrevious:')) {
        touch['_setLocationInWindow:resetPrevious:']([x, y], 0);
      }
      app.sendEvent_(event);
      console.log('[EVT] sendEvent ended');
    } catch (e) {
      console.log('[EVT] send path ERR ' + e);
    }
  }

  // Also try touchesBegan directly on view
  try {
    var set = ObjC.classes.NSSet.setWithObject_(touch);
    touch.setPhase_(0);
    view.touchesBegan_withEvent_(set, event);
    touch.setPhase_(3);
    view.touchesEnded_withEvent_(set, event);
    console.log('[VIEW] touchesBegan/Ended done');
  } catch (e) {
    console.log('[VIEW] touches ERR ' + e);
  }
}

listInteresting('UITouch');
listInteresting('UIEvent');
listInteresting('UIApplication');

ObjC.schedule(ObjC.mainQueue, function () {
  var vc = topVC();
  var reg = findRegister(vc.view());
  var cx = reg.fr.x + reg.fr.w / 2;
  var cy = reg.fr.y + reg.fr.h / 2;
  console.log('[REG] ' + cx + ',' + cy);
  synthesizeTap(cx, cy);
  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      console.log('[AFTER] ' + topVC().$className);
    });
  }, 2500);
});
