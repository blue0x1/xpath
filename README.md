# XPath - Advanced XPath Injection Scanner

Coded by Chokri Hammedi (blue0x1).
Licensed under the MIT License.
Legal use only: use on systems you own or have explicit permission to test.

A fast, multi-technique XPath injection vulnerability scanner written in Nim.
Zero external dependencies beyond the Nim standard library.

<img width="1024" height="243" alt="xpath" src="https://github.com/user-attachments/assets/2b6ed396-4048-4b47-8003-921cd53ec0a3" />



## Features

| Capability | Details |
|---|---|
| **Error-based** | 27+ signatures covering Java, .NET, PHP, Python, Saxon |
| **Boolean-based blind** | Paired TRUE/FALSE payloads with Jaccard + length similarity |
| **Time-based blind** | Response-delta detection with stacked XPath work-factor payloads |
| **Blind extraction** | Binary-search element, attribute, comment, and PI extraction |
| **Visible node-selection extraction** | `selector|/*[i]` traversal for result-limited XPath pages |
| **Auto-discovery** | Automatic parameter detection from URL query string or POST body |
| **WAF evasion** | URL-encoded, HTML-entity, comment-whitespace, mixed-case variants |
| **Auth bypass** | Position, substring, boolean, and context-aware bypass payloads |
| **Reporting** | Text and JSON report output |
| **Proxy support** | HTTP/SOCKS5 proxy, configurable User-Agent, custom headers |
| **Retry logic** | Configurable retries with exponential backoff |

## Build

```sh
# Requires Nim 2.0+
nim c -d:ssl -d:release -o:xpath src/xpath.nim
```

Or with nimble:

```sh
nimble build -d:ssl
```

Or with make:

```sh
# Linux binary: dist/xpath-linux-amd64
make linux

# Windows binary: dist/xpath-windows-amd64.exe
make windows

# Install to /usr/local/bin/xpath
sudo make install

# Build Debian package: dist/xpath_1.0.0_amd64.deb
make deb

# Remove generated build artifacts
make clean
```

## Usage

```
USAGE
  xpath [OPTIONS] -u <URL>

EXAMPLES
  # Scan a GET parameter
  xpath -u "http://target.com/login?user=admin"

  # Scan a POST form (mark injection point with *)
  xpath -u "http://target.com/login" -m POST -d "user=*&pass=test"

  # All techniques, deep payload level, extract data
  xpath -u "http://target.com/search?q=x" -t A -l 5 -x

  # Visible XPath exfiltration through a field selector
  xpath -u "http://target.com/search?q=INVALID&field=name" -p field -t U -x

  # Specific XPath expression to extract
  xpath -u "http://target.com/api?id=1" -x --xpath "//users/user[1]/password"

  # Through a proxy with custom headers
  xpath -u "http://target.com" -H "Authorization: Bearer token" \
        --proxy http://127.0.0.1:8080 -v

  # Save JSON report
  xpath -u "http://target.com/search?q=x" -t A -o report.json -f json
```

## Techniques

### `-t E` - Error-Based
Sends payloads that break XPath syntax and looks for framework-specific error
messages in the response. Fastest and most reliable technique when the
application leaks errors.

**27+ XPath error signatures** covering:
- Java (Xalan, Saxon, `javax.xml.xpath`)
- .NET (`System.Xml.XPath`, `MS.Internal.Xml.XPath`)
- PHP (`SimpleXMLElement::xpath()`)
- libxml2 (`xmlXPathEval`)
- W3C XQuery error codes (`XPST0003`, `XPST0017`, `XPTY0004`)

### `-t B` - Boolean-Based Blind
Sends paired TRUE/FALSE payloads and compares responses using:
- **Jaccard word-bag similarity** on tokenised bodies
- **Length ratio similarity** (byte-level delta)
- Combined weighted score with confidence labelling (LOW/MEDIUM/HIGH)
- Predicate pagination probes such as `position()>N` for result-limited views

### `-t T` - Time-Based Blind
Sends computationally heavy XPath expressions and measures response latency
against a 3-sample baseline average. Useful when errors are suppressed and
responses are identical regardless of query result.

The timing payload set includes stacked `count((//.)[...])` expressions that
increase XPath evaluation work when the injected expression is evaluated. Use a
conservative `--time-sec` threshold and request delay on fragile targets.

### `-t U` - Union / Node Selection
Tests whether a selector parameter can be unioned with absolute XPath paths,
for example `field=name|/*[1]/*[2]/*[1]`. This is useful for
result-limited applications where the search predicate can be made false and
the field selector controls which XML nodes are rendered.

The union probes include whole-document text-node selectors such as `//text()`,
relative parent traversal such as `../../..//text()`, and indexed absolute paths
such as `/*[1]/*[2]/*[1]/*[1]/*[1]`. They also include `//@*`,
`//comment()`, and `//processing-instruction()` for non-element data.

When other request parameters appear to control the primary search predicate,
the scanner also retries union probes with sibling parameters set to impossible
values. This catches cases where the selected field is injectable only after the
main search result set is suppressed.

When combined with `-x`, the extractor walks the document with `/*[i]` paths,
diffs visible page text against the baseline, and prints discovered leaf values.
For a visible selector parameter, use:

```sh
xpath -u "http://target.com/search?q=INVALID&field=name" -p field -t U -x
```

### `-x` - Blind Data Extraction
Once injection is confirmed, extracts XML node names and values using
**binary search over printable ASCII** (O(log n) requests per character):

1. Count total XML nodes: `count(//*)`
2. For each node: extract `name()` using `ALPHA_NUMERIC` charset
3. For each node: extract `string()` value using full printable ASCII
4. Extract attributes with `//@*`, comments with `//comment()`, and processing
   instructions with `//processing-instruction()`
5. Recursively probe child counts with `count(path/*)` when flat indexing fails
6. User-supplied `--xpath EXPR` extracts any valid XPath expression

## Payload Levels (`-l 1` to `-l 5`)

| Level | Payloads | Use case |
|---|---|---|
| 1 | Classic, universal | Quick sanity check |
| 2 | Extended standard | Most real-world apps |
| 3 | Medium (default) | Thorough scan |
| 4 | Obscure functions | Hardened apps |
| 5 | Exotic / WAF bypass | Maximum coverage |

## Response Analysis

The analyzer computes similarity between baseline, TRUE-injected, and
FALSE-injected responses to distinguish real injection from noise:

```
similarity = 0.5 × length_ratio + 0.5 × jaccard_word_similarity
```

Confidence thresholds:
- `≥ 0.9 similarity difference` → HIGH
- `≥ 0.7` → MEDIUM  
- `≥ 0.5` → LOW

## Output

```
  [+] Type       : Boolean-Based Blind
  [+] Parameter  : user
  [+] Payload    : ' or '1'='1 / ' or '1'='2
  [+] Confidence : HIGH (90%)
  [+] Evidence   : Similarity TRUE vs FALSE: 0.312 (len diff: 847 bytes)
```

JSON report (`-f json -o report.json`):

```json
{
  "scan": {
    "scanner": "xpath v1.0.0",
    "target": "http://target.com/login",
    "vuln_count": 1,
    "vulnerabilities": [
      {
        "type": "Boolean-Based Blind",
        "parameter": "user",
        "confidence": 0.9,
        "evidence": "..."
      }
    ]
  }
}
```

## Project Structure

```
src/
  xpath.nim           Main entry point
  utils/
    logger.nim        Coloured terminal logging
    config.nim        ScanConfig type and defaults
    cli.nim           Argument parsing
  core/
    payloads.nim      Payload database (auth, error, boolean, WAF)
    http.nim          HTTP engine (proxy, retries, injection helpers)
    analyzer.nim      Response similarity and error detection
    scanner.nim       Scan orchestration (error / boolean / time)
    extractor.nim     Binary-search blind data extraction
    reporter.nim      Console + JSON/text report generation
```

## Legal

This tool is for **authorised security testing only**.  
Do not use against systems you do not own or have explicit written permission to test.

MIT License - see [LICENSE](LICENSE).
