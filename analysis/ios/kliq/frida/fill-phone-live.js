// HOT-ATTACH fill probe ??? do NOT respawn Kliq
// frida -H 192.168.31.167 -n Kliq -l fill_phone_live.js -q -t 45

var NATIONAL = '7546025969';
var FULL = '447546025969';
var MODE = 'insert'; // set | insert | paste | delegate

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

function findTextFields(root, out) {
  if (!root) return;
  function walk(v, d) {
    if (!v || d > 22) return;
    if (v.$className === 'UITextField') out.push(v);
    try {
      var s = v.subviews();
      for (var i = 0; i < s.count(); i++) walk(s.objectAtIndex_(i), d + 1);
    } catch (e) {}
  }
  walk(root, 0);
}

function dumpFields(tag) {
  var vc = topVC();
  console.log('==== ' + tag + ' TOP=' + (vc ? vc.$className : 'null'));
  var fields = [];
  findTextFields(vc ? vc.view() : null, fields);
  for (var i = 0; i < fields.length; i++) {
    var tf = fields[i];
    var t = '', ph = '';
    try { t = tf.text() ? tf.text().toString() : ''; } catch (e) {}
    try { ph = tf.placeholder() ? tf.placeholder().toString() : ''; } catch (e) {}
    console.log('[TF' + i + '] text=' + JSON.stringify(t) + ' ph=' + JSON.stringify(ph) + ' first=' + tf.isFirstResponder());
  }
  return fields;
}

function fillSet(tf, value) {
  tf.becomeFirstResponder();
  tf['- setText:'](value);
  try { tf['- sendActionsForControlEvents:'](65536); } catch (e) {}
  console.log('[MODE set] now=' + (tf.text() ? tf.text().toString() : ''));
}

function fillInsert(tf, value) {
  tf.becomeFirstResponder();
  // clear
  try {
    var cur = tf.text() ? tf.text().toString() : '';
    for (var i = 0; i < cur.length + 5; i++) {
      if (tf['- deleteBackward']) tf['- deleteBackward']();
    }
  } catch (e) {}
  for (var j = 0; j < value.length; j++) {
    var ch = value.charAt(j);
    if (tf['- insertText:']) tf['- insertText:'](ch);
    else break;
  }
  try { tf['- sendActionsForControlEvents:'](65536); } catch (e) {}
  console.log('[MODE insert] now=' + (tf.text() ? tf.text().toString() : ''));
}

function fillPaste(tf, value) {
  tf.becomeFirstResponder();
  var pb = ObjC.classes.UIPasteboard.generalPasteboard();
  pb.setString_(value);
  // select all + paste via UIResponder standard actions if present
  try {
    if (tf['- selectAll:']) tf['- selectAll:'](tf);
  } catch (e) {}
  try {
    if (tf['- paste:']) tf['- paste:'](tf);
    else fillInsert(tf, value);
  } catch (e) {
    console.log('[MODE paste] err ' + e);
    fillInsert(tf, value);
  }
  console.log('[MODE paste] now=' + (tf.text() ? tf.text().toString() : ''));
}

function fillDelegate(tf, value) {
  tf.becomeFirstResponder();
  var del = null;
  try { del = tf.delegate(); } catch (e) {}
  var old = '';
  try { old = tf.text() ? tf.text().toString() : ''; } catch (e) {}
  var range = { location: 0, length: old.length };
  try {
    if (del && del['- textField:shouldChangeCharactersInRange:replacementString:']) {
      var ok = del['- textField:shouldChangeCharactersInRange:replacementString:'](tf, range, value);
      console.log('[MODE delegate] shouldChange=' + ok);
    }
  } catch (e) {
    console.log('[MODE delegate] shouldChange err ' + e);
  }
  tf['- setText:'](value);
  try {
    if (del && del['- textFieldDidChangeSelection:']) del['- textFieldDidChangeSelection:'](tf);
  } catch (e) {}
  try {
    ObjC.classes.NSNotificationCenter.defaultCenter().postNotificationName_object_(
      'UITextFieldTextDidChangeNotification',
      tf
    );
  } catch (e) {}
  try { tf['- sendActionsForControlEvents:'](65536); } catch (e) {}
  console.log('[MODE delegate] now=' + (tf.text() ? tf.text().toString() : ''));
}

ObjC.schedule(ObjC.mainQueue, function () {
  console.log('[+] fill_phone_live NATIONAL=' + NATIONAL + ' MODE=' + MODE);
  var fields = dumpFields('before');
  if (!fields.length) {
    console.log('[!] no UITextField ??? are we on phone screen?');
    return;
  }
  var tf = fields[0];
  if (MODE === 'set') fillSet(tf, NATIONAL);
  else if (MODE === 'paste') fillPaste(tf, NATIONAL);
  else if (MODE === 'delegate') fillDelegate(tf, NATIONAL);
  else fillInsert(tf, NATIONAL);

  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      dumpFields('after-0.5s');
    });
  }, 500);
  setTimeout(function () {
    ObjC.schedule(ObjC.mainQueue, function () {
      dumpFields('after-2s');
    });
  }, 2000);
});
