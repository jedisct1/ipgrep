ipgrep
======

`ipgrep` extracts possibly obfuscated host names and IP addresses from text,
resolves host names, and prints them, sorted by ASN.

Example:

```bash
$ ipgrep
hxxp://lifeiscalling-sports[.]com/8759j3f434
mebdco .com - teyseerlab,com. - meow://www.]adgroup.]ae/8759j3f434
Be careful with www.rumbafalcon\.com, it used to serve malware
```
returns
```csv
107.180.51.235	teyseerlab.com	AS26496 GoDaddy.com, LLC
166.62.10.29	mebdco.com	AS26496 GoDaddy.com, LLC
23.229.237.128	lifeiscalling-sports.com	AS26496 GoDaddy.com, LLC
162.252.57.82	www.rumbafalcon.com	AS47869 Netrouting
194.170.187.46	www.adgroup.ae	AS5384 Emirates Telecommunications Corporation
```

This is a trivial Python script, but I use it **a lot**, so I figured it might
be useful to others.

Dependencies:
```bash
$ pip install pycares
$ pip install geoip
```

The [GeoIPASNum.dat](http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz)
file is expected to be found in `/opt/geoip/GeoIPASNum.dat`, but that can be
changed by setting `GEOIPASNUM_FILE_DEFAULT` to a different value.
