// Real tap via private UITouch methods + IOHID digitizer
// frida -H 192.168.31.167 -n Kliq -l probe_hid_tap.js -q -t 45

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
    if ((v.$className || '').indexOf('HitTesting') >= 0) {
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

function call(obj, sel) {
  var args = Array.prototype.slice.call(arguments, 2);
  var m = obj['- ' + sel];
  if (!m) throw new Error('no method - ' + sel);
  return m.apply(obj, args);
}

function callApp(sel) {
  var app = ObjC.classes.UIApplication.sharedApplication();
  var m = app['- ' + sel];
  if (!m) throw new Error('no app method - ' + sel);
  return m.apply(app, Array.prototype.slice.call(arguments, 1));
}

function tapViaUITouch(x, y) {
  console.log('[A] UITouch private path');
  var app = ObjC.classes.UIApplication.sharedApplication();
  var win = app.keyWindow();
  var view = win.hitTest_withEvent_([x, y], NULL);
  console.log('[A] hit=' + view.$className);

  var touch = ObjC.classes.UITouch.alloc().init();
  call(touch, 'setWindow:', win);
  call(touch, 'setView:', view);
  call(touch, 'setTapCount:', 1);
  call(touch, 'setTimestamp:', ObjC.classes.NSProcessInfo.processInfo().systemUptime());
  call(touch, 'setPhase:', 0);
  try {
    call(touch, '_setLocationInWindow:resetPrevious:', [x, y], 1);
    console.log('[A] setLocation OK');
  } catch (e) {
    console.log('[A] setLocation ERR ' + e);
  }
  try {
    call(touch, '_setIsFirstTouchForView:', 1);
  } catch (e) {
    console.log('[A] firstTouch ERR ' + e);
  }

  var event = null;
  try {
    event = callApp('_touchesEvent');
    console.log('[A] _touchesEvent -> ' + event);
  } catch (e) {
    console.log('[A] _touchesEvent ERR ' + e);
  }
  try {
    if (!event) {
      event = callApp('_event');
      console.log('[A] _event -> ' + event);
    }
  } catch (e) {
    console.log('[A] _event ERR ' + e);
  }

  if (event) {
    try {
      if (event['- _clearTouches']) call(event, '_clearTouches');
    } catch (e) {}
    try {
      if (event['- _addTouch:forDelayedDelivery:']) {
        call(event, '_addTouch:forDelayedDelivery:', touch, 0);
        console.log('[A] addTouch OK');
      } else {
        console.log('[A] no _addTouch');
        // try _initWithEvent:touches:
      }
    } catch (e) {
      console.log('[A] addTouch ERR ' + e);
    }
    try {
      callApp('sendEvent:', event);
      console.log('[A] send began OK');
      call(touch, 'setPhase:', 3);
      callApp('sendEvent:', event);
      console.log('[A] send ended OK');
    } catch (e) {
      console.log('[A] sendEvent ERR ' + e);
    }
  }
}

function resolveIOHID() {
  var names = [
    'IOHIDEventCreateDigitizerEvent',
    'IOHIDEventCreateDigitizerFingerEvent',
    'IOHIDEventCreateDigitizerFingerEventWithQuality',
    'IOHIDEventSetSenderID',
    'IOHIDEventAppendEvent',
    'IOHIDEventCreate'
  ];
  var out = {};
  for (var i = 0; i < names.length; i++) {
    var p = Module.findExportByName(null, names[i]);
    console.log('[HID] ' + names[i] + ' = ' + p);
    out[names[i]] = p;
  }
  return out;
}

function tapViaHID(x, y) {
  console.log('[B] IOHID path');
  var exp = resolveIOHID();
  var app = ObjC.classes.UIApplication.sharedApplication();
  var win = app.keyWindow();
  var bounds = parseFrame(win.description().toString());
  var w = bounds ? bounds.w : 414;
  var h = bounds ? bounds.h : 736;
  // IOHID digitizer usually wants normalized 0..1
  var nx = x / w;
  var ny = y / h;
  console.log('[B] norm=' + nx + ',' + ny + ' win=' + w + 'x' + h);

  if (!exp.IOHIDEventCreateDigitizerFingerEvent && !exp.IOHIDEventCreateDigitizerEvent) {
    console.log('[B] no digitizer create');
    return;
  }

  // AbsoluteTime: use mach_absolute_time
  var mach_absolute_time = new NativeFunction(Module.findExportByName(null, 'mach_absolute_time'), 'uint64', []);
  var ts = mach_absolute_time();

  var event = null;
  try {
    if (exp.IOHIDEventCreateDigitizerFingerEvent) {
      // IOHIDEventRef IOHIDEventCreateDigitizerFingerEvent(
      //   CFAllocatorRef, uint64_t timeStamp,
      //   uint32_t index, uint32_t identity, uint32_t eventMask,
      //   IOHIDFloat x, y, z, tipPressure, twist,
      //   Boolean range, Boolean touch, IOOptionBits options);
      var createFinger = new NativeFunction(exp.IOHIDEventCreateDigitizerFingerEvent, 'pointer', [
        'pointer', 'uint64',
        'uint32', 'uint32', 'uint32',
        'float', 'float', 'float', 'float', 'float',
        'int', 'int', 'int'
      ]);
      // eventMask: 0x3 = touch+range? common values: 35 / 0x23 for down
      var downMask = 0x23;
      var upMask = 0x23;
      var down = createFinger(NULL, ts, 0, 2, downMask, nx, ny, 0, 0, 0, 1, 1, 0);
      console.log('[B] finger down ' + down);
      // Also parent digitizer event sometimes required
      if (exp.IOHIDEventCreateDigitizerEvent && exp.IOHIDEventAppendEvent) {
        var createDig = new NativeFunction(exp.IOHIDEventCreateDigitizerEvent, 'pointer', [
          'pointer', 'uint64',
          'int', 'uint32', 'uint32', 'uint32', 'uint32',
          'float', 'float', 'float', 'float', 'float',
          'int', 'int', 'int'
        ]);
        // transducer type hand=3?, index, identity, eventMask, buttonEventMask
        var parent = createDig(NULL, ts, 0, 0, 0, downMask, 1, nx, ny, 0, 0, 0, 1, 1, 0);
        var append = new NativeFunction(exp.IOHIDEventAppendEvent, 'void', ['pointer', 'pointer', 'int']);
        append(parent, down, 0);
        event = parent;
        console.log('[B] parent+child ' + event);
      } else {
        event = down;
      }
    }
  } catch (e) {
    console.log('[B] create ERR ' + e);
  }

  if (!event || event.isNull()) {
    console.log('[B] no event');
    return;
  }

  if (exp.IOHIDEventSetSenderID) {
    try {
      var setSender = new NativeFunction(exp.IOHIDEventSetSenderID, 'void', ['pointer', 'uint64']);
      setSender(event, uint64('0x800000081e656100'));
      console.log('[B] setSender OK');
    } catch (e) {
      console.log('[B] setSender ERR ' + e);
    }
  }

  // Deliver
  try {
    if (app['- _handleHIDEvent:']) {
      callApp('_handleHIDEvent:', event);
      console.log('[B] _handleHIDEvent down OK');
    } else if (app['- handleEvent:']) {
      callApp('handleEvent:', event);
      console.log('[B] handleEvent down OK');
    } else {
      console.log('[B] no handle HID method');
    }
  } catch (e) {
    console.log('[B] deliver down ERR ' + e);
  }

  // up
  try {
    if (exp.IOHIDEventCreateDigitizerFingerEvent) {
      var createFinger2 = new NativeFunction(exp.IOHIDEventCreateDigitizerFingerEvent, 'pointer', [
        'pointer', 'uint64',
        'uint32', 'uint32', 'uint32',
        'float', 'float', 'float', 'float', 'float',
        'int', 'int', 'int'
      ]);
      var up = createFinger2(NULL, mach_absolute_time(), 0, 2, 0x23, nx, ny, 0, 0, 0, 1, 0, 0);
      if (exp.IOHIDEventCreateDigitizerEvent && exp.IOHIDEventAppendEvent) {
        var createDig2 = new NativeFunction(exp.IOHIDEventCreateDigitizerEvent, 'pointer', [
          'pointer', 'uint64',
          'int', 'uint32', 'uint32', 'uint32', 'uint32',
          'float', 'float', 'float', 'float', 'float',
          'int', 'int', 'int'
        ]);
        var parent2 = createDig2(NULL, mach_absolute_time(), 0, 0, 0, 0x23, 1, nx, ny, 0, 0, 0, 1, 0, 0);
        var append2 = new NativeFunction(exp.IOHIDEventAppendEvent, 'void', ['pointer', 'pointer', 'int']);
        append2(parent2, up, 0);
        up = parent2;
      }
      if (app['- _handleHIDEvent:']) callApp('_handleHIDEvent:', up);
      console.log('[B] up delivered');
    }
  } catch (e) {
    console.log('[B] up ERR ' + e);
  }
}

ObjC.schedule(ObjC.mainQueue, function () {
  var vc = topVC();
  var reg = findRegister(vc.view());
  var cx = reg.fr.x + reg.fr.w / 2;
  var cy = reg.fr.y + reg.fr.h / 2;
  console.log('[REG] ' + cx + ',' + cy + ' TOP=' + vc.$className);
  tapViaUITouch(cx, cy);
  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      console.log('[AFTER-A] ' + topVC().$className);
      tapViaHID(cx, cy);
      setTimeout(function () {
        ObjC.schedule(ObjC.mainQueue, function () {
          console.log('[AFTER-B] ' + topVC().$className);
        });
      }, 2000);
    });
  }, 1500);
});
