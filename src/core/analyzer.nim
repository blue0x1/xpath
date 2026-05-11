## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

import strutils, math, sets
import payloads

type
  SimilarityScore* = object
    ratio*:         float
    lenDiff*:       int
    lenRatioDiff*:  float
    commonWords*:   float

  DetectionResult* = object
    technique*:    string
    parameter*:    string
    payload*:      string
    confidence*:   float
    evidence*:     string
    isVulnerable*: bool

proc tokenize(s: string): HashSet[string] =
  var tok = initHashSet[string]()
  for word in s.splitWhitespace():
    let w = word.strip(chars = {'"', '\'', '<', '>', '(', ')', ';', ','})
    if w.len > 2:
      tok.incl(w.toLowerAscii())
  result = tok

proc jaccardSimilarity*(a, b: string): float =
  if a.len == 0 and b.len == 0: return 1.0
  let ta = tokenize(a)
  let tb = tokenize(b)
  let intersection = ta * tb
  let union_set    = ta + tb
  if union_set.len == 0: return 1.0
  result = intersection.len.float / union_set.len.float

proc lengthSimilarity*(a, b: string): float =
  if a.len == 0 and b.len == 0: return 1.0
  let longer  = max(a.len, b.len).float
  let shorter = min(a.len, b.len).float
  result = shorter / longer

proc computeSimilarity*(a, b: string): SimilarityScore =
  result.lenDiff      = abs(a.len - b.len)
  result.lenRatioDiff = 1.0 - lengthSimilarity(a, b)
  result.commonWords  = jaccardSimilarity(a, b)
  result.ratio        = (lengthSimilarity(a, b) * 0.5 + result.commonWords * 0.5)

proc responsesAreSimilar*(a, b: string, threshold: float = 0.90): bool =
  computeSimilarity(a, b).ratio >= threshold

proc detectXpathError*(body: string): tuple[found: bool, sig: string] =
  let bodyLower = body.toLowerAscii()
  for sig in XpathErrorSignatures:
    if sig.toLowerAscii() in bodyLower:
      return (true, sig)
  result = (false, "")

proc detectGenericError*(body: string): bool =
  let bodyLower = body.toLowerAscii()
  let indicators = [
    "internal server error",
    "500 internal",
    "exception",
    "stack trace",
    "error occurred",
    "unexpected error",
    "syntax error",
    "parse error",
    "query failed",
  ]
  for ind in indicators:
    if ind in bodyLower: return true
  result = false

proc booleanDifference*(trueResp, falseResp, baseline: string): float =
  let simTF = computeSimilarity(trueResp, falseResp)
  discard baseline

  if simTF.ratio < 0.7:
    return 0.9
  elif simTF.ratio < 0.85:
    return 0.7
  elif simTF.ratio < 0.95:
    return 0.5
  else:
    return 0.0

proc isTimingAnomaly*(baseline, injected: float, threshold: float): bool =
  injected - baseline >= threshold

proc confidenceLabel*(c: float): string =
  if c >= 0.9:   "HIGH"
  elif c >= 0.7: "MEDIUM"
  elif c >= 0.5: "LOW"
  else:          "WEAK"

proc normalizeBody(s: string): string =
  s.replace("\r\n", "\n").replace("\r", "\n").strip()

proc firstDiffPos*(a, b: string): int =
  let na    = normalizeBody(a)
  let nb    = normalizeBody(b)
  let limit = min(na.len, nb.len)
  for i in 0..<limit:
    if na[i] != nb[i]: return i
  if na.len != nb.len: return limit
  return -1

proc cleanChunk(s: string, lo, maxLen: int): string =
  let hi = min(s.len, lo + maxLen)
  var chunk = s[lo..<hi]
  chunk = chunk.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
  while "  " in chunk: chunk = chunk.replace("  ", " ")
  chunk = chunk.strip()
  if lo > 0:          chunk = "..." & chunk
  if hi < s.len:      chunk = chunk & "..."
  chunk

proc diffSnippet*(baseline, injected: string, context = 140): string =
  let nb = normalizeBody(baseline)
  let ni = normalizeBody(injected)

  if nb == ni:
    return "(responses identical in content; size diff: " &
           $abs(baseline.len - injected.len) & " bytes)"

  let pos = firstDiffPos(baseline, injected)
  let lo  = max(0, pos - 40)

  let bSnip = cleanChunk(nb, lo, context)
  let iSnip = cleanChunk(ni, lo, context)

  if bSnip == iSnip:
    return "Size: baseline=" & $baseline.len & "b  injected=" &
           $injected.len & "b  (diff " & $abs(baseline.len - injected.len) & "b)"

  result = "@ byte ~" & $pos & ":\n" &
           "    baseline : " & bSnip & "\n" &
           "    injected : " & iSnip

proc errorSnippet*(body, sig: string, context = 160): string =
  let pos = body.toLowerAscii().find(sig.toLowerAscii())
  if pos < 0: return sig
  let lo = max(0, pos - 30)
  let hi = min(body.len, pos + sig.len + context)
  var chunk = body[lo..<hi]
  chunk = chunk.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
  while "  " in chunk: chunk = chunk.replace("  ", " ")
  chunk = chunk.strip()
  if lo > 0: chunk = "..." & chunk
  if hi < body.len: chunk = chunk & "..."
  result = chunk
