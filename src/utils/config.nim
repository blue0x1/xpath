## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

import strutils

type
  HttpMethodKind* = enum
    hmGet  = "GET"
    hmPost = "POST"

  TechniqueFlag* = enum
    techError
    techBoolean
    techTime
    techUnion
    techAuth

  OutputFormat* = enum
    fmtText
    fmtJson

  ScanConfig* = object
    url*:           string
    httpMethod*:    HttpMethodKind
    data*:          string
    params*:        seq[string]
    cookies*:       string
    headers*:       seq[string]
    proxy*:         string
    timeout*:       int
    delay*:         int
    retries*:       int
    followRedirects*: bool
    userAgent*:     string
    techniques*:    set[TechniqueFlag]
    level*:         int
    threads*:       int
    prefix*:        string
    suffix*:        string
    extract*:       bool
    extractExpr*:   string
    maxExtractLen*: int
    verbose*:       bool
    noColor*:       bool
    outputFile*:    string
    outputFormat*:  OutputFormat
    batch*:         bool
    timingThreshold*: float

proc defaultConfig*(): ScanConfig =
  result.httpMethod    = hmGet
  result.timeout       = 10_000
  result.delay         = 0
  result.retries       = 1
  result.followRedirects = true
  result.userAgent     = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
  result.techniques    = {techError, techBoolean}
  result.level         = 3
  result.threads       = 1
  result.maxExtractLen = 512
  result.timingThreshold = 3.0
  result.outputFormat  = fmtText

proc parseHeaders*(cfg: ScanConfig): seq[(string, string)] =
  for h in cfg.headers:
    let pos = h.find(':')
    if pos > 0:
      result.add((h[0..<pos].strip(), h[pos+1..^1].strip()))

proc parseCookies*(cfg: ScanConfig): seq[(string, string)] =
  for pair in cfg.cookies.split(';'):
    let kv = pair.strip()
    if kv.len == 0: continue
    let pos = kv.find('=')
    if pos > 0:
      result.add((kv[0..<pos].strip(), kv[pos+1..^1].strip()))
