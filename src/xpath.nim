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

when isMainModule:
  let cfg = parseCli()

  banner()

  info("Target     : " & cfg.url)
  info("Method     : " & $cfg.httpMethod)
  if cfg.data.len > 0:
    info("Data       : " & cfg.data)
  if cfg.proxy.len > 0:
    info("Proxy      : " & cfg.proxy)
  info("Techniques : " & (block:
    var ts: seq[string]
    if techError   in cfg.techniques: ts.add("Error")
    if techBoolean in cfg.techniques: ts.add("Boolean")
    if techTime    in cfg.techniques: ts.add("Time")
    if techAuth    in cfg.techniques: ts.add("Auth-Bypass")
    if techUnion   in cfg.techniques: ts.add("Union")
    ts.join(" · ")))
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
    let unionVulns = block:
      var items: seq[Vulnerability]
      for v in scanResult.vulns:
        if v.vulnType == vtUnion:
          items.add(v)
      items

    let vuln = block:
      var chosen = scanResult.vulns[0]
      var bestScore = -1.0
      for v in scanResult.vulns:
        let bodyLower = v.responseBody.toLowerAscii()
        let payloadLower = v.payload.toLowerAscii()
        let typeScore =
          case v.vulnType
          of vtUnion: 100.0
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
        let score = typeScore + payloadScore + v.confidence
        if score > bestScore:
          bestScore = score
          chosen = v
      chosen

    let extractKind =
      if vuln.vulnType == vtUnion: "visible node-selection"
      elif vuln.vulnType == vtAuth: "visible auth-response"
      else: "blind"
    info("Starting " & extractKind & " data extraction on param: " & vuln.parameter)
    echo ""

    var queryParams: Table[string, string]
    if cfg.httpMethod == hmGet:
      queryParams = parseQueryParams(cfg.url)
    else:
      queryParams = parseFormParams(cfg.data)

    if queryParams.len == 0:
      queryParams[vuln.parameter] = ""

    var extractCfg = cfg
    extractCfg.url = vuln.url   # use the form's action URL
    if vuln.responseBody.toLowerAscii().startsWith("http 302"):
      extractCfg.followRedirects = false

    var baselineBody = ""
    var positiveHtmlBodies: seq[string]
    if cfg.extractExpr.len == 0 and vuln.vulnType != vtUnion:
      let baselineResp = sendRequestWithRetry(extractCfg)
      if baselineResp.err.len == 0:
        baselineBody = baselineResp.body
      for v in scanResult.vulns:
        if v.parameter == vuln.parameter and v.responseBody.len > 0 and
           ("<" in v.responseBody or "location:" in v.responseBody.toLowerAscii()):
          positiveHtmlBodies.add(v.responseBody)

    let confirmedTrue = block:
      let slashPos = vuln.payload.find(" / ")
      if slashPos > 0: vuln.payload[0..<slashPos]
      else: vuln.payload

    if vuln.vulnType == vtUnion:
      extractResult = ExtractionResult(expr: "visible union paths")
      var seenPaths: seq[string]
      let targets =
        if cfg.extractExpr.len > 0: @[vuln]
        else: unionVulns

      for uv in targets:
        if uv.parameter != vuln.parameter:
          continue
        let seedPath = block:
          if cfg.extractExpr.len > 0: cfg.extractExpr
          else:
            let pipePos = uv.payload.find("|")
            if pipePos > 0: uv.payload[pipePos+1..^1]
            else: ""
        if seedPath.len == 0 or seedPath in seenPaths:
          continue
        seenPaths.add(seedPath)

        let selector = block:
          let pipePos = uv.payload.find("|")
          if pipePos > 0: uv.payload[0..<pipePos]
          elif uv.parameter in queryParams: queryParams[uv.parameter]
          else: ""
        let one = extractVisibleNodeSelection(extractCfg, uv.parameter,
                                              queryParams, selector, seedPath)
        extractResult.reqCount += one.reqCount
        for n in one.nodes:
          if n notin extractResult.nodes:
            extractResult.nodes.add(n)
      extractResult.nodeCount = extractResult.nodes.len
      if cfg.extractExpr.len > 0:
        extractResult.expr = cfg.extractExpr
      elif extractResult.nodes.len == 1:
        extractResult.expr = extractResult.nodes[0][0]
    elif vuln.vulnType == vtAuth and cfg.extractExpr.len == 0 and
         vuln.responseBody.len > 0:
      if "location:" in vuln.responseBody.toLowerAscii():
        extractResult = extractAuthRedirect(cfg, vuln)
      if extractResult.nodes.len == 0:
        extractResult = extractNewVisibleHtmlResponses(baselineBody, positiveHtmlBodies)
      if extractResult.nodes.len == 0:
        extractResult = extractVisibleHtmlResponse(vuln.responseBody)
    elif vuln.vulnType == vtBoolean and cfg.extractExpr.len == 0 and
         "position()>" in confirmedTrue:
      if positiveHtmlBodies.len > 0:
        extractResult = extractNewVisibleHtmlResponses(baselineBody, positiveHtmlBodies)
      if extractResult.nodes.len == 0:
        extractResult = extractVisiblePredicatePages(extractCfg, vuln.parameter,
                                                     queryParams, confirmedTrue)
    elif cfg.extractExpr.len > 0:
      var ctx = setupContext(extractCfg, vuln.parameter, queryParams, confirmedTrue)
      let val = extractExpression(ctx, cfg.extractExpr, cfg)
      extractResult = ExtractionResult(
        expr:     cfg.extractExpr,
        value:    val,
        reqCount: ctx.reqCount
      )
    else:
      var ctx = setupContext(extractCfg, vuln.parameter, queryParams, confirmedTrue)
      extractResult = extractAuto(ctx, cfg)

    printExtractionResult(extractResult)

  elif cfg.extract and scanResult.vulns.len == 0:
    warn("No confirmed injection found - skipping extraction phase.")

  saveReport(scanResult, extractResult, cfg)

  if scanResult.vulns.len > 0: quit(1)
  else: quit(0)
