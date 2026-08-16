// Broader capture: any JSON parse + URLSession resume URLs
// frida -H 192.168.31.167 -n Kliq -l capture_http_broad.js -q -t 60

if (ObjC.available) {
  Interceptor.attach(ObjC.classes.NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
    onEnter: function (args) {
      this.data = ObjC.Object(args[2]);
    },
    onLeave: function (retval) {
      try {
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(this.data, 4);
        if (!s) return;
        var t = s.toString();
        if (/question|secret|Secret|security|Security|challenge/i.test(t)) {
          console.log('[JSON] ' + t.slice(0, 3000));
        }
      } catch (e) {}
    }
  });

  var NSURLSessionTask = ObjC.classes.NSURLSessionTask;
  Interceptor.attach(NSURLSessionTask['- resume'].implementation, {
    onEnter: function (args) {
      try {
        var task = ObjC.Object(args[0]);
        var req = task.currentRequest() || task.originalRequest();
        if (req) {
          var u = req.URL().absoluteString().toString();
          if (/bpn|kliq|auth|login|secret|question|security|customer|otp/i.test(u)) {
            console.log('[REQ] ' + req.HTTPMethod().toString() + ' ' + u);
          }
        }
      } catch (e) {}
    }
  });

  console.log('[+] broad HTTP/JSON hooks ready — navigate to security questions');
}
