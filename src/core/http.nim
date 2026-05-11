## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

import httpclient, uri, strutils, tables, times, os, net
import ../utils/config, ../utils/logger

type
  HttpResponse* = object
    statusCode*: int
    body*:       string
    headers*:    Table[string, string]
    elapsed*:    float
    err*:        string
    size*:       int

proc looksEncoded*(s: string): bool =
  var i = 0
  while i + 2 < s.len:
    if s[i] == '%' and s[i + 1] in HexDigits and s[i + 2] in HexDigits:
      return true
    inc i
  result = false

proc encodeValue(v: string): string =
  if looksEncoded(v): v
  else: encodeUrl(v)

proc buildUrl*(base: string, params: Table[string, string]): string =
  if params.len == 0:
    return base
  var parts: seq[string]
  for k, v in params:
    parts.add(encodeUrl(k) & "=" & encodeValue(v))
  let sep = if '?' in base: "&" else: "?"
  result = base & sep & parts.join("&")

proc parseQueryParams*(url: string): Table[string, string] =
  let u = parseUri(url)
  if u.query.len == 0: return
  for pair in u.query.split('&'):
    let pos = pair.find('=')
    if pos > 0:
      result[decodeUrl(pair[0..<pos])] = decodeUrl(pair[pos+1..^1])

proc stripQueryString*(url: string): string =
  let pos = url.find('?')
  if pos < 0: url else: url[0..<pos]

proc parseFormParams*(body: string): Table[string, string] =
  for pair in body.split('&'):
    let pos = pair.find('=')
    if pos > 0:
      result[decodeUrl(pair[0..<pos])] = decodeUrl(pair[pos+1..^1])

proc encodeFormParams*(params: Table[string, string]): string =
  var parts: seq[string]
  for k, v in params:
    parts.add(encodeUrl(k) & "=" & encodeValue(v))
  result = parts.join("&")

proc sendRequest*(cfg: ScanConfig,
                  urlOverride: string = "",
                  bodyOverride: string = "",
                  extraHeaders: seq[(string, string)] = @[]): HttpResponse =
  let targetUrl = if urlOverride.len > 0: urlOverride else: cfg.url

  var client: HttpClient
  try:
    let tlsCtx = newContext(verifyMode = CVerifyNone)
    let redirects = if cfg.followRedirects: 5 else: 0
    if cfg.proxy.len > 0:
      client = newHttpClient(
        proxy    = newProxy(cfg.proxy),
        timeout  = cfg.timeout,
        maxRedirects = redirects,
        sslContext = tlsCtx
      )
    else:
      client = newHttpClient(timeout = cfg.timeout, maxRedirects = redirects,
                             sslContext = tlsCtx)
  except:
    return HttpResponse(err: "Failed to create HTTP client: " & getCurrentExceptionMsg())

  client.headers = newHttpHeaders({
    "User-Agent": cfg.userAgent,
    "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
  })

  for (k, v) in cfg.parseHeaders():
    client.headers[k] = v
  for (k, v) in extraHeaders:
    client.headers[k] = v

  if cfg.cookies.len > 0:
    client.headers["Cookie"] = cfg.cookies

  let t0 = epochTime()
  try:
    var resp: Response
    let meth = if cfg.httpMethod == hmPost: HttpPost else: HttpGet

    if cfg.httpMethod == hmPost:
      let body = if bodyOverride.len > 0: bodyOverride else: cfg.data
      if "Content-Type" notin client.headers.table:
        client.headers["Content-Type"] = @["application/x-www-form-urlencoded"]
      resp = client.request(targetUrl, httpMethod = meth, body = body)
    else:
      resp = client.request(targetUrl, httpMethod = meth)

    let elapsed = epochTime() - t0
    var hdrs: Table[string, string]
    for k, v in resp.headers.pairs():
      hdrs[k.toLowerAscii()] = v

    var bodyText = resp.body
    if bodyText.len == 0 and resp.code.int >= 300 and resp.code.int < 400:
      bodyText = "HTTP " & $resp.code.int
      if "location" in hdrs:
        bodyText.add("\nLocation: " & hdrs["location"])
      if "set-cookie" in hdrs:
        bodyText.add("\nSet-Cookie: " & hdrs["set-cookie"])

    result = HttpResponse(
      statusCode: resp.code.int,
      body:       bodyText,
      headers:    hdrs,
      elapsed:    elapsed,
      size:       bodyText.len
    )
  except TimeoutError:
    result = HttpResponse(err: "Timeout", elapsed: epochTime() - t0)
  except:
    result = HttpResponse(err: getCurrentExceptionMsg(), elapsed: epochTime() - t0)
  finally:
    client.close()

  if cfg.delay > 0:
    os.sleep(cfg.delay)

proc sendRequestWithRetry*(cfg: ScanConfig,
                           urlOverride: string = "",
                           bodyOverride: string = "",
                           extraHeaders: seq[(string, string)] = @[]): HttpResponse =
  for attempt in 0 ..< max(1, cfg.retries):
    result = sendRequest(cfg, urlOverride, bodyOverride, extraHeaders)
    if result.err.len == 0:
      return
    if attempt < cfg.retries - 1:
      debug("Retry " & $(attempt+2) & "/" & $cfg.retries & " after error: " & result.err)
      os.sleep(500 * (attempt + 1))

proc injectParam*(baseUrl: string,
                  paramName: string,
                  payload: string,
                  originalParams: Table[string, string]): string =
  var params = originalParams
  params[paramName] = payload
  buildUrl(stripQueryString(baseUrl), params)

proc injectBody*(template_body: string,
                 paramName: string,
                 payload: string,
                 originalParams: Table[string, string]): string =
  if '*' in template_body:
    return template_body.replace("*", payload)
  var params = originalParams
  params[paramName] = payload
  encodeFormParams(params)
