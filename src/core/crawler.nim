## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

## HTML form and input crawler.
## Parses raw HTML to extract <form> elements and their fields,
## resolves relative action URLs, and returns ready-to-scan targets.

import strutils, uri
import ../utils/config, ../utils/logger

type
  FieldKind* = enum
    fkText, fkPassword, fkHidden, fkSearch,
    fkTextarea, fkSelect, fkRadio, fkCheckbox, fkOther

  FormField* = object
    name*:  string
    kind*:  FieldKind
    value*: string

  DetectedForm* = object
    action*:     string
    httpMethod*: HttpMethodKind
    fields*:     seq[FormField]
    raw*:        string

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
  of "radio":           fkRadio
  of "checkbox":        fkCheckbox
  of "text", "email",
     "tel", "number",
     "url", "":         fkText
  of "submit", "button",
     "reset", "image",
     "file":            fkOther
  else:                 fkOther

proc decodeHtml(s: string): string =
  result = s
    .replace("&nbsp;", " ")
    .replace("&lt;", "<")
    .replace("&gt;", ">")
    .replace("&amp;", "&")
    .replace("&quot;", "\"")
    .replace("&#39;", "'")
    .replace("&#039;", "'")

proc findTagEnd(html: string, start: int): int =
  var quote = '\0'
  var i = start
  while i < html.len:
    let ch = html[i]
    if quote != '\0':
      if ch == quote:
        quote = '\0'
    elif ch == '"' or ch == '\'':
      quote = ch
    elif ch == '>':
      return i
    inc i
  result = -1

proc tagName(tag: string): string =
  var i = 0
  while i < tag.len and tag[i] in {'<', '/', ' ', '\t', '\r', '\n'}:
    inc i
  let start = i
  while i < tag.len and tag[i] notin {' ', '\t', '\r', '\n', '/', '>'}:
    inc i
  if i > start:
    result = tag[start ..< i].toLowerAscii()

proc parseAttrs(tag: string): seq[(string, string)] =
  var i = 0
  while i < tag.len and tag[i] != '<':
    inc i
  if i < tag.len:
    inc i
  while i < tag.len and tag[i] in {'/', ' ', '\t', '\r', '\n'}:
    inc i
  while i < tag.len and tag[i] notin {' ', '\t', '\r', '\n', '/', '>'}:
    inc i

  while i < tag.len:
    while i < tag.len and tag[i] in {' ', '\t', '\r', '\n', '/', '>'}:
      inc i
    if i >= tag.len:
      break

    let nameStart = i
    while i < tag.len and tag[i] notin {' ', '\t', '\r', '\n', '=', '/', '>'}:
      inc i
    if i <= nameStart:
      break
    let name = tag[nameStart ..< i].toLowerAscii()

    while i < tag.len and tag[i] in {' ', '\t', '\r', '\n'}:
      inc i

    var value = ""
    if i < tag.len and tag[i] == '=':
      inc i
      while i < tag.len and tag[i] in {' ', '\t', '\r', '\n'}:
        inc i
      if i < tag.len and (tag[i] == '"' or tag[i] == '\''):
        let quote = tag[i]
        inc i
        let valueStart = i
        while i < tag.len and tag[i] != quote:
          inc i
        value = tag[valueStart ..< min(i, tag.len)].decodeHtml()
        if i < tag.len:
          inc i
      else:
        let valueStart = i
        while i < tag.len and tag[i] notin {' ', '\t', '\r', '\n', '/', '>'}:
          inc i
        value = tag[valueStart ..< i].decodeHtml()

    result.add((name, value))

proc attrValue(attrs: seq[(string, string)], name: string): string =
  let target = name.toLowerAscii()
  for (k, v) in attrs:
    if k == target:
      return v
  result = ""

proc hasAttribute(attrs: seq[(string, string)], name: string): bool =
  let target = name.toLowerAscii()
  for (k, _) in attrs:
    if k == target:
      return true
  result = false

proc selectedValue(selectHtml: string): string =
  let low = selectHtml.toLowerAscii()
  var pos = 0
  var firstValue = ""
  while true:
    let start = low.find("<option", pos)
    if start < 0:
      break
    let gt = findTagEnd(selectHtml, start)
    if gt < 0:
      break
    let tag = selectHtml[start .. gt]
    let attrs = parseAttrs(tag)
    let closeStart = low.find("</option>", gt + 1)
    let text =
      if closeStart >= 0: selectHtml[gt + 1 ..< closeStart].decodeHtml().strip()
      else: ""
    let attr = attrs.attrValue("value")
    let value = if attr.len > 0: attr else: text
    if firstValue.len == 0:
      firstValue = value
    if attrs.hasAttribute("selected"):
      return value
    pos = if closeStart >= 0: closeStart + 9 else: gt + 1
  result = firstValue

proc plainText(html: string): string =
  var inTag = false
  for ch in html:
    case ch
    of '<': inTag = true
    of '>':
      inTag = false
      result.add(' ')
    else:
      if not inTag:
        result.add(ch)
  result = result.decodeHtml().strip()

proc addFieldsFromForm(formHtml: string, form: var DetectedForm) =
  let low = formHtml.toLowerAscii()
  var pos = 0
  while true:
    let start = low.find("<", pos)
    if start < 0:
      break
    let gt = findTagEnd(formHtml, start)
    if gt < 0:
      break
    let tag = formHtml[start .. gt]
    let name = tagName(tag)
    let attrs = parseAttrs(tag)

    case name
    of "input":
      let fieldName = attrs.attrValue("name")
      if fieldName.len > 0:
        let kind = fieldKindOf(attrs.attrValue("type"))
        if kind != fkOther:
          form.fields.add(FormField(
            name: fieldName,
            kind: kind,
            value: attrs.attrValue("value")
          ))
      pos = gt + 1
    of "textarea":
      let closeStart = low.find("</textarea>", gt + 1)
      let content =
        if closeStart >= 0: formHtml[gt + 1 ..< closeStart].plainText()
        else: ""
      let fieldName = attrs.attrValue("name")
      if fieldName.len > 0:
        form.fields.add(FormField(
          name: fieldName,
          kind: fkTextarea,
          value: content
        ))
      pos = if closeStart >= 0: closeStart + 11 else: gt + 1
    of "select":
      let closeStart = low.find("</select>", gt + 1)
      let content =
        if closeStart >= 0: formHtml[start ..< closeStart + 9]
        else: tag
      let fieldName = attrs.attrValue("name")
      if fieldName.len > 0:
        form.fields.add(FormField(
          name: fieldName,
          kind: fkSelect,
          value: selectedValue(content)
        ))
      pos = if closeStart >= 0: closeStart + 9 else: gt + 1
    else:
      pos = gt + 1

proc crawlForms*(html, pageUrl: string): seq[DetectedForm] =
  let low = html.toLowerAscii()
  var pos = 0
  while true:
    let start = low.find("<form", pos)
    if start < 0:
      break
    let gt = findTagEnd(html, start)
    if gt < 0:
      break
    let closeStart = low.find("</form>", gt + 1)
    if closeStart < 0:
      break

    let formTag = html[start .. gt]
    let attrs = parseAttrs(formTag)
    let formHtml = html[gt + 1 ..< closeStart]
    let action = attrs.attrValue("action")
    let meth = attrs.attrValue("method").toUpperAscii()
    var form = DetectedForm(
      action: resolveUrl(pageUrl, action),
      httpMethod: if meth == "POST": hmPost else: hmGet,
      raw: html[start ..< closeStart + 7]
    )

    addFieldsFromForm(formHtml, form)

    if form.fields.len > 0:
      result.add(form)

    pos = closeStart + 7

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
        of fkRadio:    " [radio]"
        of fkCheckbox: " [checkbox]"
        else:          ""
      info("    param: " & field.name & kindStr)

proc formParts(form: DetectedForm, injectParam: string,
               injectValue: string): seq[(string, string)] =
  var seen: seq[string]
  for f in form.fields:
    if f.name in seen:
      continue
    seen.add(f.name)
    let v = if f.name == injectParam: injectValue else: f.value
    result.add((f.name, v))

proc formToPostBody*(form: DetectedForm, injectParam: string,
                     injectValue: string): string =
  var parts: seq[string]
  for (name, value) in form.formParts(injectParam, injectValue):
    parts.add(encodeUrl(name) & "=" & encodeUrl(value))
  result = parts.join("&")

proc formToGetUrl*(form: DetectedForm, injectParam: string,
                   injectValue: string): string =
  var parts: seq[string]
  for (name, value) in form.formParts(injectParam, injectValue):
    parts.add(encodeUrl(name) & "=" & encodeUrl(value))
  let sep = if '?' in form.action: "&" else: "?"
  result = form.action & sep & parts.join("&")
