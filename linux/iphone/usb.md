pip install pymobiledevice3


pymobiledevice3 usbmux forward <LOCAL_WINDOWS_PORT> <IPHONE_PORT>

pymobiledevice3 usbmux forward 2222 22


100.90.48.112 root ssh


http://127.0.0.1:8081/?token=ff519e2c5d292c0604101381cffff5be

mitmweb --web-host 0.0.0.0 --listen-host 0.0.0.0

mitmweb --web-host 188.166.252.16 --listen-host 188.166.252.16

mitmweb --web-host 0.0.0.0 --listen-host 188.166.252.16


!~u \.jpg$
this hides any request where the url ends specifically in ".jpg".

!~u \.(jpg|jpeg)$
this catches both ".jpg" and ".jpeg" extensions in the url.

!~t image/jpeg
this is often more reliable. it filters by the response's content-type header, so it will hide the image even if the url doesn't explicitly have a .jpg extension.

!~t image/.*
if your goal is just to clear up visual clutter from all pictures, use this. it hides all image types (jpg, png, gif, webp, etc.) based on their content-type header.