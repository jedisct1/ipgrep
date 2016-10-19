ipgrep
======

`ipgrep` extracts possibly obfuscated host names and IP addresses from text,
resolves host names, and prints them, sorted by ASN.

Example:

```bash
$ ipgrep
hxxp://lifeiscalling-sports[.]com/8759j3f434 - 199[.]88[.]59[.]22
mebdco .com - teyseerlab,com. - meow://www.]adgroup.]ae/8759j3f434
Be careful with www.rumbafalcon\.com, it used to serve malware
```
returns
```csv
107.180.51.235	teyseerlab.com.	AS26496: AS-26496-GO-DADDY-COM-LLC - GoDaddy.com, LLC (US)
166.62.10.29	mebdco.com	AS26496: AS-26496-GO-DADDY-COM-LLC - GoDaddy.com, LLC (US)
23.229.237.128	lifeiscalling-sports.com	AS26496: AS-26496-GO-DADDY-COM-LLC - GoDaddy.com, LLC (US)
199.88.59.22	-	AS40539: PROHCI - Hosting Consulting, Inc (US)
162.252.57.82	www.rumbafalcon.com.	AS47869: NETROUTING-AS (NL)
194.170.187.46	www.adgroup.ae	AS5384: EMIRATES-INTERNET Emirates Internet (AE)
```

This is a trivial Python script, but I use it **a lot**, so I figured it might
be useful to others.

Dependencies:
```bash
$ pip install pycares
$ pip install sortedcontainers
```

The uncompressed [ip2asn-v4-u32.tsv](https://iptoasn.com/)
file is expected to be found in `/opt/ip2asn/ip2asn-v4-u32.tsv`, but that can be
changed by setting `IP2ASN_FILE_DEFAULT` to a different value.
