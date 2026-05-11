## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

import strutils, tables
import utils/logger, utils/cli, utils/config
import core/http, core/scanner, core/extractor, core/reporter, core/crawler

proc needsCrawl(cfg: ScanConfig): bool =
  if cfg.params.len > 0: return false
  if cfg.httpMethod == hmPost and cfg.data.len > 0: return false
  return true

proc headerLineValue(body, name: string): string =
  let prefix = name.toLowerAscii() & ":"
  for line in body.splitLines():
    let stripped = line.strip()
    if stripped.toLowerAscii().startsWith(prefix):
      return stripped[prefix.len .. ^1].strip()
  result = ""

proc cookiePair(setCookie: string): string =
  if setCookie.len == 0:
    return ""
  let semi = setCookie.find(";")
  result = if semi >= 0: setCookie[0 ..< semi].strip() else: setCookie.strip()

proc extractAuthRedirect*(cfg: ScanConfig, vuln: Vulnerability): ExtractionResult =
  result.expr = "auth redirect follow-up"

  let location = headerLineValue(vuln.responseBody, "Location")
  if location.len == 0:
    return

  let targetUrl = resolveUrl(vuln.url, location)
  result.nodes.add(("redirect", location))
  finding("redirect", location)

  var followCfg = cfg
  followCfg.url = targetUrl
  followCfg.httpMethod = hmGet
  followCfg.followRedirects = true

  var headers: seq[(string, string)]
  let setCookie = headerLineValue(vuln.responseBody, "Set-Cookie")
  let cookie = cookiePair(setCookie)
  if cookie.len > 0:
    let merged =
      if cfg.cookies.len > 0: cfg.cookies & "; " & cookie
      else: cookie
    headers.add(("Cookie", merged))

  let resp = sendRequestWithRetry(followCfg, urlOverride = targetUrl,
                                  extraHeaders = headers)
  result.reqCount = 1
  if resp.err.len > 0:
    result.nodes.add(("follow-up error", resp.err))
    result.nodeCount = result.nodes.len
    return

  result.nodes.add(("follow-up status", "HTTP " & $resp.statusCode))
  if resp.body.len > 0:
    let parsed = extractVisibleHtmlResponse(resp.body, "page")
    for node in parsed.nodes:
      if node notin result.nodes:
        result.nodes.add(node)
  result.nodeCount = result.nodes.len

proc techniquesText(cfg: ScanConfig): string =
  var ts: seq[string]
  if techError in cfg.techniques: ts.add("Error")
  if techBoolean in cfg.techniques: ts.add("Boolean")
  if techTime in cfg.techniques: ts.add("Time")
  if techAuth in cfg.techniques: ts.add("Auth-Bypass")
  if techUnion in cfg.techniques: ts.add("Union")
  result = ts.join(" · ")

proc collectUnionVulns(scanResult: ScanResult): seq[Vulnerability] =
  for v in scanResult.vulns:
    if v.vulnType == vtUnion:
      result.add(v)

proc extractionScore(v: Vulnerability): float =
  let bodyLower = v.responseBody.toLowerAscii()
  let payloadLower = v.payload.toLowerAscii()
  let typeScore =
    case v.vulnType
    of vtUnion: 130.0
    of vtAuth:
      if "internal server error" in bodyLower: 5.0
      elif "location:" in bodyLower and "login failed" notin bodyLower: 99.0
      elif "<tr" in bodyLower: 98.0
      elif "<" in v.responseBody: 96.0
      else: 30.0
    of vtBoolean:
      if "location:" in bodyLower: 40.0
      elif "<tr" in bodyLower: 88.0
      elif "position()>" in v.payload: 95.0
      else: 80.0
    of vtTime: 40.0
    of vtError: 10.0

  let payloadScore =
    if v.vulnType == vtAuth:
      if "contains" in payloadLower and
         ("admin" in payloadLower or "root" in payloadLower or "priv" in payloadLower or
          "owner" in payloadLower or "manager" in payloadLower or
          "operator" in payloadLower or "staff" in payloadLower): 6.0
      elif "position()=3" in payloadLower: 4.0
      elif "position()=2" in payloadLower: 3.0
      elif "position()=last()" in payloadLower: 2.0
      else: 0.0
    else:
      0.0
  result = typeScore + payloadScore + v.confidence

proc chooseExtractionVuln(scanResult: ScanResult): Vulnerability =
  result = scanResult.vulns[0]
  var bestScore = -1.0
  let pool =
    if collectUnionVulns(scanResult).len > 0: collectUnionVulns(scanResult)
    else: scanResult.vulns
  for v in pool:
    let score = extractionScore(v)
    if score > bestScore:
      bestScore = score
      result = v

proc extractionKind(v: Vulnerability): string =
  case v.vulnType
  of vtUnion: "visible node-selection"
  of vtAuth: "visible auth-response"
  else: "blind"

proc requestParams(cfg: ScanConfig, param, sourceUrl: string): Table[string, string] =
  if cfg.httpMethod == hmGet:
    let url = if sourceUrl.len > 0: sourceUrl else: cfg.url
    result = parseQueryParams(url)
  else:
    result = parseFormParams(cfg.data)
  if result.len == 0:
    result[param] = ""

proc positiveBodies(scanResult: ScanResult, param: string): seq[string] =
  for v in scanResult.vulns:
    if v.parameter == param and v.responseBody.len > 0 and
       ("<" in v.responseBody or "location:" in v.responseBody.toLowerAscii()):
      result.add(v.responseBody)

proc confirmedTruePayload(v: Vulnerability): string =
  let slashPos = v.payload.find(" / ")
  if slashPos > 0: v.payload[0..<slashPos] else: v.payload

proc unionSeedPath(cfg: ScanConfig, uv: Vulnerability): string =
  if cfg.extractExpr.len > 0:
    return cfg.extractExpr
  let pipePos = uv.payload.find("|")
  if pipePos > 0:
    return uv.payload[pipePos + 1 .. ^1]
  result = ""

proc unionSelector(uv: Vulnerability,
                   queryParams: Table[string, string]): string =
  let pipePos = uv.payload.find("|")
  if pipePos > 0:
    return uv.payload[0 ..< pipePos]
  if uv.parameter in queryParams:
    return queryParams[uv.parameter]
  result = ""

proc extractUnionData(cfg: ScanConfig,
                      vulns: seq[Vulnerability],
                      chosen: Vulnerability,
                      queryParams: Table[string, string]): ExtractionResult =
  result = ExtractionResult(expr: "visible union paths")
  var seenPaths: seq[string]
  let targets = if cfg.extractExpr.len > 0: @[chosen] else: vulns

  for uv in targets:
    if uv.parameter != chosen.parameter:
      continue
    let seedPath = unionSeedPath(cfg, uv)
    if seedPath.len == 0 or seedPath in seenPaths:
      continue
    seenPaths.add(seedPath)

    let selector = unionSelector(uv, queryParams)
    let one = extractVisibleNodeSelection(cfg, uv.parameter, queryParams,
                                          selector, seedPath)
    result.reqCount += one.reqCount
    for n in one.nodes:
      if n notin result.nodes:
        result.nodes.add(n)

  result.nodeCount = result.nodes.len
  if cfg.extractExpr.len > 0:
    result.expr = cfg.extractExpr
  elif result.nodes.len == 1:
    result.expr = result.nodes[0][0]

proc runExtraction(cfg: ScanConfig, scanResult: ScanResult): ExtractionResult =
  if not cfg.extract or scanResult.vulns.len == 0:
    return

  let vuln = chooseExtractionVuln(scanResult)
  info("Starting " & extractionKind(vuln) &
       " data extraction on param: " & vuln.parameter)
  echo ""

  let queryParams = requestParams(cfg, vuln.parameter, vuln.url)
  let confirmedTrue = confirmedTruePayload(vuln)

  var extractCfg = cfg
  extractCfg.url = vuln.url
  if vuln.responseBody.toLowerAscii().startsWith("http 302"):
    extractCfg.followRedirects = false

  var baselineBody = ""
  var positiveHtmlBodies: seq[string]
  if cfg.extractExpr.len == 0 and vuln.vulnType != vtUnion:
    let baselineResp = sendRequestWithRetry(extractCfg)
    if baselineResp.err.len == 0:
      baselineBody = baselineResp.body
    positiveHtmlBodies = positiveBodies(scanResult, vuln.parameter)

  case vuln.vulnType
  of vtUnion:
    result = extractUnionData(extractCfg, collectUnionVulns(scanResult),
                              vuln, queryParams)
  of vtAuth:
    if cfg.extractExpr.len == 0 and vuln.responseBody.len > 0:
      if "location:" in vuln.responseBody.toLowerAscii():
        result = extractAuthRedirect(cfg, vuln)
      if result.nodes.len == 0:
        result = extractNewVisibleHtmlResponses(baselineBody, positiveHtmlBodies)
      if result.nodes.len == 0:
        result = extractVisibleHtmlResponse(vuln.responseBody)
    elif cfg.extractExpr.len > 0:
      var ctx = setupContext(extractCfg, vuln.parameter, queryParams, confirmedTrue)
      let val = extractExpression(ctx, cfg.extractExpr, cfg)
      result = ExtractionResult(expr: cfg.extractExpr, value: val, reqCount: ctx.reqCount)
  of vtBoolean:
    if cfg.extractExpr.len == 0 and "position()>" in confirmedTrue:
      if positiveHtmlBodies.len > 0:
        result = extractNewVisibleHtmlResponses(baselineBody, positiveHtmlBodies)
      if result.nodes.len == 0:
        result = extractVisiblePredicatePages(extractCfg, vuln.parameter,
                                              queryParams, confirmedTrue)
    elif cfg.extractExpr.len > 0:
      var ctx = setupContext(extractCfg, vuln.parameter, queryParams, confirmedTrue)
      let val = extractExpression(ctx, cfg.extractExpr, cfg)
      result = ExtractionResult(expr: cfg.extractExpr, value: val, reqCount: ctx.reqCount)
    else:
      var ctx = setupContext(extractCfg, vuln.parameter, queryParams, confirmedTrue)
      result = extractAuto(ctx, cfg)
  else:
    if cfg.extractExpr.len > 0:
      var ctx = setupContext(extractCfg, vuln.parameter, queryParams, confirmedTrue)
      let val = extractExpression(ctx, cfg.extractExpr, cfg)
      result = ExtractionResult(expr: cfg.extractExpr, value: val, reqCount: ctx.reqCount)
    else:
      var ctx = setupContext(extractCfg, vuln.parameter, queryParams, confirmedTrue)
      result = extractAuto(ctx, cfg)

when isMainModule:
  let cfg = parseCli()

  banner()

  info("Target     : " & cfg.url)
  info("Method     : " & $cfg.httpMethod)
  if cfg.data.len > 0:
    info("Data       : " & cfg.data)
  if cfg.proxy.len > 0:
    info("Proxy      : " & cfg.proxy)
  info("Techniques : " & techniquesText(cfg))
  info("Level      : " & $cfg.level)
  echo ""

  var scanResult: ScanResult

  if needsCrawl(cfg):
    info("No parameters detected - crawling page for HTML forms...")
    echo ""
    scanResult = scanCrawled(cfg)
  else:
    scanResult = scan(cfg)

  printSummary(scanResult)

  var extractResult: ExtractionResult

  if cfg.extract and scanResult.vulns.len > 0:
    extractResult = runExtraction(cfg, scanResult)
    printExtractionResult(extractResult)

  elif cfg.extract and scanResult.vulns.len == 0:
    warn("No confirmed injection found - skipping extraction phase.")

  saveReport(scanResult, extractResult, cfg)

  if scanResult.vulns.len > 0: quit(1)
  else: quit(0)
