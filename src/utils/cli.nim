## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

import strutils, os
import config, logger

proc usage() =
  echo """
USAGE
  xpath [OPTIONS] -u <URL>

TARGET
  -u, --url <URL>           Target URL (required)
  -m, --method <METHOD>     HTTP method: GET (default) | POST
  -d, --data <DATA>         POST body (use * to mark injection point)
  -p, --param <PARAM>       Parameter(s) to test (comma-separated)
  -c, --cookie <COOKIE>     Cookie string (k=v; k2=v2)
  -H, --header <HEADER>     Extra header "Name: Value" (repeatable)

NETWORK
      --proxy <URL>         HTTP proxy (e.g. http://127.0.0.1:8080)
      --timeout <MS>        Request timeout in ms (default: 10000)
      --delay <MS>          Delay between requests in ms (default: 0)
      --retries <N>         Retry count on failure (default: 1)
  -A, --user-agent <UA>     Custom User-Agent string
      --no-redirect         Do not follow HTTP redirects

DETECTION
  -t, --technique <FLAGS>   Techniques to use (default: EB)
                              E = Error-based
                              B = Boolean-based blind
                              T = Time-based blind
                              U = Union/node-selection extraction
                              P = Auth bypass (single-payload)
                              A = All techniques
  -l, --level <1-5>         Payload thoroughness level (default: 3)
      --prefix <STR>        Injection prefix override
      --suffix <STR>        Injection suffix override
      --time-sec <SEC>      Time-based delay threshold (default: 3)

EXTRACTION
  -x, --extract             Extract data after confirming injection
      --xpath <EXPR>        XPath expression to extract (default: auto)
      --max-len <N>         Max characters to extract (default: 512)

OUTPUT
  -v, --verbose             Verbose / debug output
      --no-color            Disable ANSI colour codes
  -o, --output <FILE>       Save report to file
  -f, --format <FMT>        Output format: text (default) | json
  -b, --batch               No interactive prompts

  -h, --help                Show this help
      --version             Show version

EXAMPLES
  xpath -u "http://example.com/login?user=admin"
  xpath -u "http://example.com/login" -m POST -d "user=*&pass=test" -t EB
  xpath -u "http://example.com/search?q=test" -t A -l 5 -x
  xpath -u "http://example.com/page" -p q -t A -l 5 -x
  xpath -u "http://example.com/api" -H "X-API-Key: secret" --proxy http://127.0.0.1:8080
"""

proc parseTechniques(s: string): set[TechniqueFlag] =
  for ch in s.toUpperAscii():
    case ch
    of 'E': result.incl(techError)
    of 'B': result.incl(techBoolean)
    of 'T': result.incl(techTime)
    of 'U': result.incl(techUnion)
    of 'P': result.incl(techAuth)
    of 'A': return {techError, techBoolean, techTime, techUnion, techAuth}
    else: discard

const SHORT_FLAGS = {'v', 'x', 'b', 'h'}
const LONG_FLAGS  = ["no-redirect", "no-color", "verbose", "extract",
                     "batch", "help", "version"]

proc applyKV(cfg: var ScanConfig, key, val: string) =
  case key.toLowerAscii()
  of "url",         "u": cfg.url = val
  of "method",      "m": cfg.httpMethod = if val.toUpperAscii() == "POST": hmPost else: hmGet
  of "data",        "d": cfg.data = val; cfg.httpMethod = hmPost
  of "param",       "p":
    for par in val.split(','):
      let t = par.strip()
      if t.len > 0: cfg.params.add(t)
  of "cookie",      "c": cfg.cookies = val
  of "header",      "H": cfg.headers.add(val)
  of "proxy":            cfg.proxy = val
  of "timeout":
    try: cfg.timeout = parseInt(val) except: discard
  of "delay":
    try: cfg.delay = parseInt(val) except: discard
  of "retries":
    try: cfg.retries = parseInt(val) except: discard
  of "user-agent",  "A": cfg.userAgent = val
  of "technique",   "t": cfg.techniques = parseTechniques(val)
  of "level",       "l":
    try: cfg.level = parseInt(val).clamp(1, 5) except: discard
  of "prefix":           cfg.prefix = val
  of "suffix":           cfg.suffix = val
  of "time-sec":
    try: cfg.timingThreshold = parseFloat(val) except: discard
  of "xpath":            cfg.extractExpr = val
  of "max-len":
    try: cfg.maxExtractLen = parseInt(val) except: discard
  of "output",      "o": cfg.outputFile = val
  of "format",      "f": cfg.outputFormat = if val.toLowerAscii() == "json": fmtJson else: fmtText
  else: warn("Unknown option: --" & key)

proc applyFlag(cfg: var ScanConfig, key: string) =
  case key.toLowerAscii()
  of "v", "verbose":    cfg.verbose = true; gVerbose = true
  of "x", "extract":   cfg.extract = true
  of "b", "batch":     cfg.batch   = true
  of "h", "help":      usage(); quit(0)
  of "no-redirect":    cfg.followRedirects = false
  of "no-color":       cfg.noColor = true; gNoColor = true
  of "version":        echo "xpath 1.0.0"; quit(0)
  else: warn("Unknown flag: --" & key)

proc parseCli*(): ScanConfig =
  var cfg  = defaultConfig()
  let args = commandLineParams()
  var i    = 0

  while i < args.len:
    let arg = args[i]

    if arg == "--":
      inc i
      while i < args.len:
        if cfg.url.len == 0: cfg.url = args[i]
        inc i
      break

    elif arg.startsWith("--"):
      let rest  = arg[2..^1]
      let eqPos = rest.find('=')
      if eqPos >= 0:
        applyKV(cfg, rest[0..<eqPos], rest[eqPos+1..^1])
      elif rest in LONG_FLAGS:
        applyFlag(cfg, rest)
      else:
        inc i
        if i >= args.len:
          error("Expected a value after --" & rest); quit(1)
        applyKV(cfg, rest, args[i])

    elif arg.startsWith("-") and arg.len > 1:
      var j = 1
      while j < arg.len:
        let ch  = arg[j]
        let key = $ch
        inc j

        if ch in SHORT_FLAGS:
          applyFlag(cfg, key)

        elif j < arg.len:
          let val = if arg[j] == '=': arg[j+1..^1] else: arg[j..^1]
          applyKV(cfg, key, val)
          j = arg.len

        else:
          if i + 1 < args.len and not args[i + 1].startsWith("-"):
            inc i
            applyKV(cfg, key, args[i])
          else:
            applyFlag(cfg, key)

    else:
      if cfg.url.len == 0:
        cfg.url = arg
      else:
        warn("Ignoring unexpected argument: " & arg)

    inc i

  if cfg.techniques.len == 0:
    cfg.techniques = {techError, techBoolean}

  if cfg.url.len == 0:
    error("Target URL is required. Use -u <URL> or --help for usage.")
    quit(1)

  if not cfg.url.startsWith("http://") and not cfg.url.startsWith("https://"):
    cfg.url = "http://" & cfg.url

  result = cfg
