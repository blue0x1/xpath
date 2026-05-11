## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

## HTML form and input crawler.
## Parses raw HTML to extract <form> elements and their fields,
## resolves relative action URLs, and returns ready-to-scan targets.

import strutils, uri, tables
import ../utils/config, ../utils/logger

type
  FieldKind* = enum
    fkText, fkPassword, fkHidden, fkSearch,
    fkTextarea, fkSelect, fkOther

  FormField* = object
    name*:  string
    kind*:  FieldKind
    value*: string

  DetectedForm* = object
    action*:     string
    httpMethod*: HttpMethodKind
    fields*:     seq[FormField]
    raw*:        string


proc extractAttr(tag, attr: string): string =
  let needle = attr & "="
  var i = tag.toLowerAscii().find(needle)
  if i < 0: return ""
  i += needle.len
  if i >= tag.len: return ""
  let q = tag[i]
  if q == '"' or q == '\'':
    let close = tag.find(q, i + 1)
    if close < 0: return tag[i+1..^1]
    return tag[i+1..<close]
  else:
    var j = i
    while j < tag.len and tag[j] notin {' ', '\t', '\n', '\r', '>'}:
      inc j
    return tag[i..<j]

proc hasAttr(tag, attr: string): bool =
  tag.toLowerAscii().contains(attr & "=") or
  tag.toLowerAscii().contains(" " & attr & " ") or
  tag.toLowerAscii().contains(" " & attr & ">")

proc tagName(tag: string): string =
  var i = 0
  while i < tag.len and tag[i] in {'<', '/'}: inc i
  var j = i
  while j < tag.len and tag[j] notin {' ', '\t', '\n', '\r', '>', '/'}:
    inc j
  result = tag[i..<j].toLowerAscii()


iterator tags(html: string): tuple[tag: string, pos: int] =
  var i = 0
  while i < html.len:
    if html[i] == '<':
      if i + 3 < html.len and html[i+1..i+3] == "!--":
        let close = html.find("-->", i + 3)
        i = if close < 0: html.len else: close + 3
        continue
      let nameStart = i + 1
      var ni = nameStart
      while ni < html.len and html[ni] notin {' ', '\t', '\n', '\r', '>', '/'}:
        inc ni
      let tn = html[nameStart..<ni].toLowerAscii()
      if tn == "script" or tn == "style":
        let closeTag = "</" & tn & ">"
        let close = html.toLowerAscii().find(closeTag, i + 1)
        i = if close < 0: html.len else: close + closeTag.len
        continue
      var j = i + 1
      var inQ = '\0'
      while j < html.len:
        let ch = html[j]
        if inQ != '\0':
          if ch == inQ: inQ = '\0'
        elif ch == '"' or ch == '\'':
          inQ = ch
        elif ch == '>':
          break
        inc j
      if j < html.len:
        yield (html[i..j], i)
        i = j + 1
      else:
        break
    else:
      inc i


proc resolveUrl*(base, href: string): string =
  if href.len == 0:
    return base
  if href.startsWith("http://") or href.startsWith("https://"):
    return href
  let bu = parseUri(base)
  if href.startsWith("//"):
    return bu.scheme & ":" & href
  if href.startsWith("/"):
    return bu.scheme & "://" & bu.hostname &
           (if bu.port.len > 0: ":" & bu.port else: "") & href
  var dir = bu.path
  let sl = dir.rfind('/')
  if sl >= 0: dir = dir[0..sl]
  else: dir = "/"
  let combined = bu.scheme & "://" & bu.hostname &
                 (if bu.port.len > 0: ":" & bu.port else: "") &
                 dir & href
  result = combined

proc fieldKindOf(typeAttr: string): FieldKind =
  case typeAttr.toLowerAscii()
  of "password":        fkPassword
  of "hidden":          fkHidden
  of "search":          fkSearch
  of "text", "email",
     "tel", "number",
     "url", "":         fkText
  else:                 fkOther

proc crawlForms*(html, pageUrl: string): seq[DetectedForm] =
  var
    inForm   = false
    curForm  = DetectedForm()
    formBuf  = ""

  for (tag, _) in tags(html):
    let tn = tagName(tag)

    case tn
    of "form":
      if tag.startsWith("</"):
        if inForm:
          result.add(curForm)
          curForm  = DetectedForm()
          inForm   = false
          formBuf  = ""
      else:
        inForm = true
        let action = extractAttr(tag, "action")
        let meth   = extractAttr(tag, "method").toUpperAscii()
        curForm = DetectedForm(
          action:     resolveUrl(pageUrl, action),
          httpMethod: if meth == "POST": hmPost else: hmGet,
          raw:        tag
        )

    of "input":
      if not inForm: continue
      let name = extractAttr(tag, "name")
      if name.len == 0: continue
      let typeAttr = extractAttr(tag, "type")
      let kind     = fieldKindOf(typeAttr)
      if kind == fkOther: continue
      let value = extractAttr(tag, "value")
      curForm.fields.add(FormField(name: name, kind: kind, value: value))

    of "textarea":
      if not inForm: continue
      let name = extractAttr(tag, "name")
      if name.len == 0: continue
      curForm.fields.add(FormField(name: name, kind: fkTextarea, value: ""))

    of "select":
      if not inForm: continue
      let name = extractAttr(tag, "name")
      if name.len == 0: continue
      curForm.fields.add(FormField(name: name, kind: fkSelect, value: "1"))

    else: discard

  if inForm and curForm.fields.len > 0:
    result.add(curForm)

proc printForms*(forms: seq[DetectedForm]) =
  if forms.len == 0:
    warn("No HTML forms detected on the target page.")
    return
  info("Found " & $forms.len & " form(s):")
  for i, f in forms:
    info("  Form #" & $(i+1) & "  [" & $f.httpMethod & "]  " & f.action)
    for field in f.fields:
      let kindStr = case field.kind
        of fkPassword: " [password]"
        of fkHidden:   " [hidden]"
        of fkSearch:   " [search]"
        of fkTextarea: " [textarea]"
        of fkSelect:   " [select]"
        else:          ""
      info("    param: " & field.name & kindStr)

proc formToPostBody*(form: DetectedForm, injectParam: string,
                     injectValue: string): string =
  var parts: seq[string]
  for f in form.fields:
    let v = if f.name == injectParam: injectValue else: f.value
    parts.add(encodeUrl(f.name) & "=" & encodeUrl(v))
  result = parts.join("&")

proc formToGetUrl*(form: DetectedForm, injectParam: string,
                   injectValue: string): string =
  var parts: seq[string]
  for f in form.fields:
    let v = if f.name == injectParam: injectValue else: f.value
    parts.add(encodeUrl(f.name) & "=" & encodeUrl(v))
  let sep = if '?' in form.action: "&" else: "?"
  result = form.action & sep & parts.join("&")
