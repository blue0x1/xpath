## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

## HTML form and input crawler.
## Parses raw HTML to extract <form> elements and their fields,
## resolves relative action URLs, and returns ready-to-scan targets.

import strutils, uri, htmlparser, xmltree, strtabs
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


proc attrValue(node: XmlNode, name: string): string =
  result = node.attr(name)

proc hasAttribute(node: XmlNode, name: string): bool =
  node.kind == xnElement and node.attrs != nil and node.attrs.hasKey(name)

proc nodeText(node: XmlNode): string =
  case node.kind
  of xnText, xnVerbatimText, xnCData, xnEntity:
    result.add(node.text)
  else:
    for child in node.items:
      result.add(nodeText(child))


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

proc selectedValue(selectNode: XmlNode): string =
  var firstValue = ""
  for option in selectNode.findAll("option", caseInsensitive = true):
    let value = block:
      let attr = option.attrValue("value")
      if attr.len > 0: attr else: option.nodeText().strip()
    if firstValue.len == 0:
      firstValue = value
    if option.hasAttribute("selected"):
      return value
  result = firstValue

proc formFieldNodes(formNode: XmlNode): seq[XmlNode] =
  for child in formNode.findAll("input", caseInsensitive = true):
    result.add(child)
  for child in formNode.findAll("textarea", caseInsensitive = true):
    result.add(child)
  for child in formNode.findAll("select", caseInsensitive = true):
    result.add(child)

proc crawlForms*(html, pageUrl: string): seq[DetectedForm] =
  let doc = parseHtml(html)
  for formNode in doc.findAll("form", caseInsensitive = true):
    let action = formNode.attrValue("action")
    let meth = formNode.attrValue("method").toUpperAscii()
    var form = DetectedForm(
      action: resolveUrl(pageUrl, action),
      httpMethod: if meth == "POST": hmPost else: hmGet,
      raw: $formNode
    )

    for fieldNode in formNode.formFieldNodes():
      let name = fieldNode.attrValue("name")
      if name.len == 0:
        continue

      case fieldNode.tag.toLowerAscii()
      of "input":
        let kind = fieldKindOf(fieldNode.attrValue("type"))
        if kind == fkOther:
          continue
        form.fields.add(FormField(
          name: name,
          kind: kind,
          value: fieldNode.attrValue("value")
        ))
      of "textarea":
        form.fields.add(FormField(
          name: name,
          kind: fkTextarea,
          value: fieldNode.nodeText()
        ))
      of "select":
        form.fields.add(FormField(
          name: name,
          kind: fkSelect,
          value: fieldNode.selectedValue()
        ))
      else:
        discard

    if form.fields.len > 0:
      result.add(form)

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
