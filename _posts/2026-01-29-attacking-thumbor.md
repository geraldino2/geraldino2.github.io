---
layout: post
title: Attacking thumbor
date: 2026-01-29 00:00:00
description: parser differential between tornado and urlparse, ReDoS, bruteforce, misconfigurations
tags: writeup web server-side parser-differential
categories: cybersec
featured: true
---

[thumbor](https://github.com/thumbor/thumbor) is an open-source image processing server, similar to [Cloudflare Images](https://developers.cloudflare.com/images/) or [imgproxy](https://imgproxy.net/).

The easiest way to send an image to be treated by it is to use unsafe URLs, [enabled by default](https://github.com/thumbor/thumbor/blob/f83495a819d5d417317fc3dbf7a4d10872b4f15f/thumbor/config.py#L385-L390), in the format [http://thumbor-server/unsafe/300x300/smart/path/to/image.jpg](http://thumbor-server/unsafe/300x300/path/to/image.jpg). An obvious problem is that attackers can manipulate the options passed to the server; thumbor relates this security issue to a possibility of [DoS through spam](https://github.com/thumbor/thumbor/blob/f83495a819d5d417317fc3dbf7a4d10872b4f15f/docs/security.rst) and recommends to use HMAC signed URLs as a solution.

This blog post covers:

- Domain whitelist bypass via a parser differential between `tornado` and `urlparse`;
- Single request denial of service through ReDoS;
- Attacking the HMAC security key via brute force;
- Some other random stuff.

## Domain whitelist bypass

thumbor provides multiple configurations to harden what the server can do, such as `MAX_WIDTH` or `ALLOWED_SOURCES`; the latter defines which FQDNs thumbor can download images from.

The call stack trace on processing an external image is quite long, but it all starts on `handlers/imaging.py:get` and the most important methods related to download are on `loaders/http_loader.py`. `loaders/http_loader.py:validate` validates if the given URL is within the whitelist defined by `ALLOWED_SOURCES` and `loaders/http_loader.py:load` is responsible for the download itself. After a lot of simplifications, the code for both functions look like this:

```python
import re
import tornado
from urllib.parse import urlparse

def validate(context, url):
    res = urlparse(url)
    for pattern in context.config.ALLOWED_SOURCES:
        pattern = f"^{pattern}$"
        match = res.hostname
        if re.match(pattern, match):
            return True
    return False
async def load(url):
    return tornado.httpclient.HTTPRequest(url=url)
```

`ALLOWED_SOURCES` is an array of FQDNs. The function uses `urllib` to extract the FQDN from an URL and compares it to each value from the array. If the validation succeeds, the URL is passed to `load`. There's one problem with this approach: `thumbor` doesn't have a guarantee that `tornado` will use the same URL parser used on `validate`.

Going deep into `tornado` one can see that it indeed uses `urllib`, but it also implements its own logic to separate hosts from ports. A simplified version of the code is provided below:

```python
import re
from urllib.parse import urlsplit

def parse_url_host_port(url: str) -> tuple[str, int | None]:
    netloc = urlsplit(url).netloc
    _netloc_re = re.compile(r"^(.+):(\d+)$")
    match = _netloc_re.match(netloc)
    if match:
        host = match.group(1)
        port = int(match.group(2))
    else:
        host = netloc
        port = None
    return host, port
```

Note that `tornado` restricts ports to integer numbers, while `urlparse` doesn't. An URL such as `http://allowed-domain.com:.evil.com` will be seen by `validate` as containing an allowed hostname (`allowed-domain.com` as a hostname and `.evil.com` as a port), but `tornado` says that the hostname is actually `allowed-domain.com:.evil.com`.

Although `allowed-domain.com:.evil.com` is technically not a valid FQDN, `tornado` uses `socket.getaddrinfo` to get the IP address; this method considers `evil.com` to be the hostname, bypassing the whitelist.

## ReDoS

Regular expressions can take up to exponential time to evaluate, and excessive use of resources may cause a denial of service ([CWE-1333](https://cwe.mitre.org/data/definitions/1333.html)). The [Cloudflare outage in 2019](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/) is probably the most well-known example of that.

Besides resizing images, thumbor can also apply filters to them. Filters use regexes. Multiple defined filters can take up to exponential or polynomial time to evaluate. An exhaustive list of them won't be provided, but the `convolution` filter is an example: `/convolution\((?:\s*((?:[-]?[\d]+\.?[\d]*[;])*(?:[-]?[\d]+\.?[\d]*))\s*)(?:,\s*([\d]+)\s*)(?:,\s*([Tt]rue|[Ff]alse|1|0)\s*)?\)/` is $O(2^n)$.

[`http://thumbor-server/unsafe/0x0/smart/filters:convolution(-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11)/x.png` ](<http://thumbor-server/unsafe/0x0/smart/filters:convolution(-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11;-11)/x.png>)causes the call to `re.match` on [`thumbor/thumbor/filters/__init__.py#L189`](https://github.com/thumbor/thumbor/blob/f83495a819d5d417317fc3dbf7a4d10872b4f15f/thumbor/filters/__init__.py#L189) to take too long and stalls the server.

## Brute force attack on HMAC

For some reason the documentation states that the `SECURITY_KEY` for HMAC should be [up to 16 characters](https://github.com/thumbor/thumbor/blob/f83495a819d5d417317fc3dbf7a4d10872b4f15f/thumbor/thumbor.conf#x:~:text=16%20characters). The code, however, doesn't implement that limit and it's actually better to use longer and complex keys.

Given an URL defined as [`http://thumbor-server/hash-signature/0x0/smart/x.png` ](http://thumbor-server/hash-signature/0x0/smart/x.png), , the signature will be defined on top of `0x0/smart/x.png`. As the default URL signer computes the signature as the code below, it's trivial to use brute force or dictionary attacks against weak keys.

```python
def signature(self, url):
    return base64.urlsafe_b64encode(
        hmac.new(
            self.security_key, text_type(url).encode("utf-8"), hashlib.sha1
        ).digest()
    )
```

## Miscellaneous

- Documentation says that it's possible to define a callback function for JSONP in the configuration file (`META_CALLBACK_NAME`). Although not documented, it's also possible to do it in the URL: [http://thumbor-server/unsafe/meta/0x0/smart/x.png?callback=foobar](http://thumbor-server/unsafe/meta/0x0/smart/x.png?callback=foobar);
- It's possible, and potentially dangerous, to have uploads enabled with a non-default configuration of `UPLOAD_ENABLED`;
- `USE_BLACKLIST` is also a non-default configuration that enables unprivileged users to add URLs to a blacklist. The blacklist is case sensitive and doesn't process the URL in any way.
