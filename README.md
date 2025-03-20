# mobileScripts
Python + Frida scripts

## BinaryCookieDecoder.py
A like-for-like Python3 port of https://github.com/as0ler/BinaryCookieReader to decode Apple binary cookie files which actually works. Run with:
```
python3 BinaryCookieDecoder.py -f PATH_TO_BINARY_COOKIE_FILE
```
## InspectFileAccess.js
A Frida script for iOS to see what local files are loaded during runtime. Run with:
```
frida -l InspectFileAccess.js -f <<APP-IDENTIFIER>>
```

