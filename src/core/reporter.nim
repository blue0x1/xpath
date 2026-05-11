## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

import strutils, times, json
import ../utils/config, ../utils/logger
import scanner, extractor, analyzer

const
  cReset = "\e[0m"
  cPink = "\e[38;2;255;82;168m"
  cRose = "\e[38;2;231;36;113m"
  cLilac = "\e[38;2;178;112;255m"
  cSoft = "\e[38;2;255;228;240m"
  cFoundBg = "\e[48;2;92;12;48m"

proc printSeparator(ch: string = "-", width = 70) =
  var line = ""
  for _ in 0..<width: line.add(ch)
  if gNoColor:
    echo line
  else:
    stdout.write(cLilac & line & cReset & "\n")
  stdout.flushFile()

proc printVulnerability*(v: Vulnerability, idx: int) =
  printSeparator()
  if gNoColor:
    echo "[VULNERABILITY #" & $idx & "]"
  else:
    stdout.write(cFoundBg & cRose & "  VULNERABILITY #" & $idx & cReset & "\n")

  finding("Type",       $v.vulnType)
  finding("Parameter",  v.parameter)
  finding("Payload",    v.payload)
  finding("Confidence", confidenceLabel(v.confidence) &
                        " (" & (v.confidence * 100).toInt.intToStr & "%)")
  finding("Evidence",   v.evidence)
  if v.diffContext.len > 0:
    for line in v.diffContext.splitLines():
      if line.len > 0:
        finding("Diff",     line)

proc vulnRank(v: Vulnerability): float =
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
      else: 60.0
    of vtBoolean:
      if "location:" in bodyLower: 40.0
      elif "<tr" in bodyLower: 88.0
      elif "position()>" in payloadLower: 85.0
      else: 70.0
    of vtTime: 45.0
    of vtError: 20.0
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

proc compactVulns(vulns: seq[Vulnerability]): seq[Vulnerability] =
  var keys: seq[string]
  for v in vulns:
    let key = v.parameter & "|" & $v.vulnType
    let idx = keys.find(key)
    if idx < 0:
      keys.add(key)
      result.add(v)
    elif vulnRank(v) > vulnRank(result[idx]):
      result[idx] = v

proc printSummary*(result: ScanResult) =
  echo ""
  printSeparator("=")
  if gNoColor:
    echo "SCAN SUMMARY"
  else:
    stdout.write(cPink & "  SCAN SUMMARY" & cReset & "\n")
  printSeparator("=")

  finding("Target",         result.target)
  finding("Parameters",     result.testedParams.join(", "))
  finding("Requests Sent",  $result.requestCount)
  finding("Duration",       result.duration.formatFloat(ffDecimal, 2) & "s")

  let shown = compactVulns(result.vulns)

  if result.vulns.len == 0:
    if gNoColor:
      echo "  [=] No XPath injection vulnerabilities detected."
    else:
      stdout.write(cSoft & "  [=] No XPath injection vulnerabilities detected." & cReset & "\n")
  else:
    if gNoColor:
      echo "  [!] " & $shown.len & " finding(s) shown from " & $result.vulns.len & " confirmed"
    else:
      stdout.write(cFoundBg & cRose & "  [!] " & $shown.len & " finding(s) shown from " & $result.vulns.len & " confirmed" & cReset & "\n")
    echo ""
    for i, v in shown:
      printVulnerability(v, i + 1)

  echo ""
  printSeparator()

proc printExtractionResult*(er: ExtractionResult) =
  echo ""
  printSeparator("=")
  if gNoColor:
    echo "EXTRACTION RESULTS"
  else:
    stdout.write(cPink & "  EXTRACTION RESULTS" & cReset & "\n")
  printSeparator("=")

  finding("Expression",  er.expr)
  finding("Node Count",  $er.nodeCount)
  finding("Requests",    $er.reqCount)

  if er.value.len > 0:
    echo ""
    finding("Value", er.value)
  elif er.nodes.len > 0:
    echo ""
    for (name, val) in er.nodes:
      if name.len > 0 or val.len > 0:
        if name.startsWith("/") or name.startsWith("..") or
           name.startsWith("@") or name.startsWith("pi:") or
           name.startsWith("comment") or "//" in name:
          finding(name, val)
        else:
          finding("<" & name & ">", val)
  else:
    warn("No data could be extracted.")
  echo ""


proc toJsonScan*(res: ScanResult): JsonNode =
  var vulnArr = newJArray()
  for v in res.vulns:
    var obj = newJObject()
    obj["type"] = %($v.vulnType)
    obj["parameter"] = %(v.parameter)
    obj["payload"] = %(v.payload)
    obj["confidence"] = %(v.confidence)
    obj["evidence"] = %(v.evidence)
    obj["diff_context"] = %(v.diffContext)
    vulnArr.add(obj)

  var paramsArr = newJArray()
  for param in res.testedParams:
    paramsArr.add(%param)

  result = newJObject()
  result["scanner"] = %"xpath v1.0.0"
  result["timestamp"] = %(now().format("yyyy-MM-dd'T'HH:mm:ss"))
  result["target"] = %(res.target)
  result["params"] = paramsArr
  result["requests"] = %(res.requestCount)
  result["duration"] = %(res.duration)
  result["vuln_count"] = %(res.vulns.len)
  result["vulnerabilities"] = vulnArr

proc toJsonExtract*(er: ExtractionResult): JsonNode =
  var nodesArr = newJArray()
  for (name, val) in er.nodes:
    var obj = newJObject()
    obj["name"] = %(name)
    obj["value"] = %(val)
    nodesArr.add(obj)

  result = newJObject()
  result["expression"] = %(er.expr)
  result["node_count"] = %(er.nodeCount)
  result["nodes"] = nodesArr
  result["value"] = %(er.value)

proc saveReport*(scanResult: ScanResult,
                 extractResult: ExtractionResult,
                 cfg: ScanConfig) =
  if cfg.outputFile.len == 0: return

  var content = ""
  if cfg.outputFormat == fmtJson:
    var root = newJObject()
    root["scan"] = toJsonScan(scanResult)
    if extractResult.expr.len > 0:
      root["extraction"] = toJsonExtract(extractResult)
    content = root.pretty()
  else:
    content  = "XPath Scanner Report\n"
    content &= "====================\n"
    content &= "Target   : " & scanResult.target & "\n"
    content &= "Params   : " & scanResult.testedParams.join(", ") & "\n"
    content &= "Requests : " & $scanResult.requestCount & "\n"
    content &= "Duration : " & scanResult.duration.formatFloat(ffDecimal, 2) & "s\n\n"
    content &= "Vulnerabilities Found: " & $scanResult.vulns.len & "\n\n"
    for i, v in scanResult.vulns:
      content &= "--- Vulnerability #" & $(i+1) & " ---\n"
      content &= "Type      : " & $v.vulnType & "\n"
      content &= "Parameter : " & v.parameter & "\n"
      content &= "Payload   : " & v.payload & "\n"
      content &= "Confidence: " & confidenceLabel(v.confidence) & "\n"
      content &= "Evidence  : " & v.evidence & "\n"
      if v.diffContext.len > 0:
        content &= "Diff      : " & v.diffContext & "\n"
      content &= "\n"
    if extractResult.nodes.len > 0:
      content &= "--- Extracted Data ---\n"
      for (name, val) in extractResult.nodes:
        content &= "<" & name & "> " & val & "\n"

  try:
    writeFile(cfg.outputFile, content)
    success("Report saved to: " & cfg.outputFile)
  except:
    error("Failed to save report: " & getCurrentExceptionMsg())
