// frida -U -f com.hxgy.hxgyapp -l bypass-vpn.js -q -t inf
// VPN/proxy detection bypass for 华医通 (Shadowrocket utun hop).
// MODE 'log':   enumerate interfaces + proxy settings, backtrace the alert. Find the checker.
// MODE 'block': neuter +[APPSafe environmentSafety] (the checker — shows 警告/运行环境异常 then force-exits).
//               Generic ifaddrs/proxy rewrites stay OFF: emptying the proxy dict would cut
//               the app off from mitmweb — we want capture AND bypass, not direct traffic.
var MODE = 'block';

var VPN_IF = /^(utun|ipsec|ppp|tun|tap)/;

function filterIfaddrs(head) {
  // struct ifaddrs: ifa_next@0, ifa_name@8 (64-bit)
  var prev = null;
  var cur = head;
  var kept = head;
  while (!cur.isNull()) {
    var next = cur.readPointer();
    var name = cur.add(8).readPointer().readCString() || '';
    if (VPN_IF.test(name)) {
      console.log('[ifaddrs] hide ' + name);
      if (prev) prev.writePointer(next); else kept = next;
    } else {
      console.log('[ifaddrs] keep ' + name);
      prev = cur;
    }
    cur = next;
  }
  return kept;
}

// Frida 17: static Module.findExportByName is gone
function findExport(modName, sym) {
  if (modName) {
    var m = Process.findModuleByName(modName);
    return m ? m.findExportByName(sym) : null;
  }
  return Module.findGlobalExportByName
    ? Module.findGlobalExportByName(sym)
    : Module.findExportByName(null, sym);
}

// --- getifaddrs / proxy (log mode only — noisy, and rewriting them would cut mitmweb) ---
if (MODE === 'log') {
  var getifaddrs = findExport(null, 'getifaddrs');
  if (getifaddrs) {
    Interceptor.attach(getifaddrs, {
      onEnter: function (args) { this.out = args[0]; },
      onLeave: function (retval) {
        if (retval.toInt32() !== 0) return;
        try {
          var head = this.out.readPointer();
          var cur = head;
          while (!cur.isNull()) {
            console.log('[ifaddrs] ' + (cur.add(8).readPointer().readCString() || ''));
            cur = cur.readPointer();
          }
        } catch (e) { console.log('[ifaddrs] err ' + e); }
      }
    });
    console.log('hooked getifaddrs');
  }

  var cfProxy = findExport('CFNetwork', 'CFNetworkCopySystemProxySettings');
  if (cfProxy) {
    Interceptor.attach(cfProxy, {
      onLeave: function (retval) {
        try {
          var d = new ObjC.Object(retval);
          console.log('[proxy] settings: ' + d.toString());
        } catch (e) { console.log('[proxy] err ' + e); }
      }
    });
    console.log('hooked CFNetworkCopySystemProxySettings');
  }
}

// --- NEVPNManager (only if the app links NetworkExtension) ---
if (ObjC.classes.NEVPNManager) {
  var conn = ObjC.classes.NEVPNConnection;
  if (conn && conn['- status']) {
    Interceptor.attach(conn['- status'].implementation, {
      onLeave: function (retval) {
        console.log('[NEVPN] status=' + retval);
      }
    });
    console.log('hooked NEVPNConnection -status');
  }
}

// --- surgical: +[APPSafe environmentSafety] (found via alert backtrace 2026-08-15) ---
// Shows 警告 "系统检测到您的APP运行环境异常…APP将强制退出" then kills the app.
var APPSafe = ObjC.classes.APPSafe;
if (APPSafe) {
  try { console.log('[APPSafe] methods: ' + APPSafe.$ownMethods.join(' ')); } catch (e) {}
  var es = APPSafe['+ environmentSafety'];
  if (es) {
    if (MODE === 'block') {
      Interceptor.replace(es.implementation, new NativeCallback(function () {
        console.log('[APPSafe] environmentSafety neutered');
      }, 'void', []));
      console.log('hooked +[APPSafe environmentSafety] -> noop');
    } else {
      Interceptor.attach(es.implementation, {
        onEnter: function () { console.log('[APPSafe] environmentSafety called'); },
        onLeave: function (r) { console.log('[APPSafe] ret=' + r); }
      });
    }
  }
}

// --- who shows the VPN alert: log + backtrace on alert presentation ---
var VC = ObjC.classes.UIViewController;
Interceptor.attach(VC['- presentViewController:animated:completion:'].implementation, {
  onEnter: function (args) {
    try {
      var vc = new ObjC.Object(args[2]);
      var name = vc.$className;
      var msg = '';
      if (name.indexOf('Alert') >= 0) {
        try { msg += ' title=' + vc.title(); } catch (e) {}
        try { msg += ' msg=' + vc.message(); } catch (e) {}
      }
      console.log('[present] ' + name + msg);
      if (/vpn|VPN|代理|网络|环境/.test(msg) || MODE === 'log') {
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
          .map(DebugSymbol.fromAddress).join('\n'));
      }
    } catch (e) {}
  }
});

console.log('bypass-vpn loaded · MODE=' + MODE);
