## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

import unittest, tables, json, strutils, sequtils

import ../src/core/analyzer
import ../src/core/crawler
import ../src/core/extractor
import ../src/core/http
import ../src/core/reporter
import ../src/core/scanner
import ../src/utils/config

suite "HTML crawler":
  test "parses forms with quoted attributes and rich fields":
    let html = """
      <html><body>
        <form method='post' action='/login.php'>
          <input type="text" name="username" value='a "quoted" value'>
          <input type=password name=pass>
          <input type="radio" name="format" value="long">
          <input type="radio" name="format" value="short">
          <textarea name='note'>hello &amp; welcome</textarea>
          <select name="role">
            <option value="user">User</option>
            <option selected value="admin">Admin</option>
          </select>
        </form>
      </body></html>
    """
    let forms = crawlForms(html, "https://example.test/app/index.php")
    check forms.len == 1
    check forms[0].action == "https://example.test/login.php"
    check forms[0].httpMethod == hmPost
    check forms[0].fields.len == 6
    check forms[0].fields[0].name == "username"
    check forms[0].fields[0].value == "a \"quoted\" value"
    check forms[0].fields[1].kind == fkPassword
    check forms[0].fields[2].kind == fkRadio
    check forms[0].fields[2].name == "format"
    check forms[0].fields[4].kind == fkTextarea
    check "hello" in forms[0].fields[4].value
    check forms[0].fields[5].value == "admin"

  test "deduplicates radio groups when building request data":
    let html = """
      <form method="get" action="/index.php">
        <input name="q" value="xpathscan">
        <input type="radio" name="f" value="fullstreetname">
        <input type="radio" name="f" value="streetname">
      </form>
    """
    let form = crawlForms(html, "http://example.test/")[0]
    let url = formToGetUrl(form, "f", "fullstreetname|//text()")
    check "q=xpathscan" in url
    check "f=fullstreetname%7C%2F%2Ftext%28%29" in url
    check url.count("f=") == 1

suite "HTTP parameter helpers":
  test "does not double encode already encoded payloads":
    var params = initTable[string, string]()
    params["q"] = "base"
    let payload = "%27%29%5D%2F..%2F*%5B1%5D%5Btext%28%29%21%3D%28%27"
    let url = injectParam("https://example.test/search?q=base", "q", payload, params)
    check "%2527" notin url
    check payload in url

  test "parses query parameters":
    let params = parseQueryParams("https://example.test/?q=a%20b&f=fullstreetname")
    check params["q"] == "a b"
    check params["f"] == "fullstreetname"

suite "Analyzer":
  test "detects XPath parser errors":
    let (found, sig) = detectXpathError("javax.xml.xpath.XPathExpressionException: invalid token")
    check found
    check sig.len > 0

  test "computes response similarity":
    check responsesAreSimilar("alpha beta gamma", "alpha beta gamma")
    check not responsesAreSimilar("alpha beta gamma", "one two three", 0.95)

suite "JSON reporter":
  test "escapes special characters in scan and extraction output":
    let vuln = Vulnerability(
      url: "https://example.test/?q=\"x\"",
      parameter: "q\"name",
      vulnType: vtBoolean,
      payload: "' or \"x\"\n and '1'='1",
      confidence: 0.72,
      evidence: "line one\nline \"two\"",
      diffContext: "tab\tquote\"",
      responseBody: ""
    )
    let scan = ScanResult(
      target: "https://example.test/?q=\"x\"",
      vulns: @[vuln],
      testedParams: @["q\"name"],
      requestCount: 3,
      duration: 0.25
    )
    let scanJson = parseJson($toJsonScan(scan))
    check scanJson["vulnerabilities"][0]["payload"].getStr == vuln.payload
    check scanJson["params"][0].getStr == "q\"name"

    let extract = ExtractionResult(
      expr: "//text()",
      value: "value \"quoted\"\nnext",
      nodeCount: 1,
      nodes: @[("node\"1", "value\n2")],
      reqCount: 1
    )
    let extractJson = parseJson($toJsonExtract(extract))
    check extractJson["nodes"][0]["name"].getStr == "node\"1"
    check extractJson["value"].getStr == "value \"quoted\"\nnext"

suite "Visible HTML extraction":
  test "skips table headers structurally and keeps row text":
    let html = """
      <table>
        <tr><th>Name</th><th>Action</th></tr>
        <tr><td>secret.txt</td><td><a href="/download?id=1">Download</a></td></tr>
      </table>
    """
    let er = extractVisibleHtmlResponse(html)
    check er.nodes.len == 1
    check "secret.txt" in er.nodes[0][1]
    check "Download" in er.nodes[0][1]
    check "/download?id=1" in er.nodes[0][1]

  test "prioritizes secret-like context in large br-separated dumps":
    var html = "<center><b>Results:</b><br><br>"
    for i in 1..160:
      html.add("STREET " & $i & "<br>STREET<br>")
    html.add("""
      <br>student<br>
      <br>295362c2618a05ba3899904a6a3f5bc0<br>
      <br>Training Account<br>
      <br>admin<br>
      <br>21232f297a57a5a743894a0e4a801fc3<br>
      <br>APP{47975e37f044ff05065b66f6733f86ba}<br>
    </center>
    """)
    let er = extractVisibleHtmlResponse(html)
    let joined = er.nodes.mapIt(it[1]).join(" | ")
    check "APP{47975e37f044ff05065b66f6733f86ba}" in joined
    check "admin" in joined
    check er.nodes[0][1] != "STREET 1"
