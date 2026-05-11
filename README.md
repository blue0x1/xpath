# xpath

<p align="center">
  <img width="1024" height="243" alt="xpath" src="https://github.com/user-attachments/assets/2b6ed396-4048-4b47-8003-921cd53ec0a3" />
</p>

<p align="center">
  <b>Advanced XPath injection scanner for authorized security testing.</b>
</p>

<p align="center">
  <img alt="version" src="https://img.shields.io/badge/version-1.0.0-ff52a8?style=for-the-badge">
  <img alt="language" src="https://img.shields.io/badge/Nim-2.0%2B-f3c143?style=for-the-badge">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-9b6cff?style=for-the-badge">
  <img alt="platform" src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-202124?style=for-the-badge">
</p>

<p align="center">
  Coded by <b>Chokri Hammedi</b> (<b>blue0x1</b>) · MIT Licensed
</p>

---

## Overview

`xpath` is a fast, multi-technique XPath injection scanner written in Nim. It focuses on practical detection, response comparison, visible extraction, blind extraction, and payload coverage for real-world XML-backed applications.

It has no external runtime dependencies beyond the Nim standard library.

## Capabilities

| Area | Support |
|---|---|
| Detection | Error-based, boolean-based blind, time-based blind, auth bypass, union/node-selection |
| Extraction | Visible HTML parsing, selector union extraction, blind XPath data extraction |
| Payloads | Classic, predicate, function-based, path breakout, encoded, entity, mixed-case variants |
| Discovery | URL parameter detection and HTML form crawling |
| Evasion | WAF/IDS indicators, URL-encoded and entity-based bypass payloads |
| Output | Human-readable terminal report and JSON report export |
| Transport | Cookies, headers, proxy, retry, timeout, User-Agent, redirect controls |

## Installation

### Nimble

```bash
nimble install xpath
```

This installs the latest package from the official Nim package list.

### Build From Source

```bash
git clone https://github.com/blue0x1/xpath.git
cd xpath
make linux
make test
```

The Linux binary is written to:

```text
dist/xpath-linux-amd64
```

### Install System-Wide

```bash
sudo make install
```

By default this installs:

```text
/usr/local/bin/xpath
```

To change the install prefix:

```bash
sudo make install PREFIX=/usr
```

### Debian Package

```bash
make deb
sudo dpkg -i dist/xpath_1.0.0_amd64.deb
```

### Windows Cross Build

```bash
make windows
```

The Windows binary is written to:

```text
dist/xpath-windows-amd64.exe
```

On Linux, the Windows build requires MinGW:

```bash
sudo apt install mingw-w64
```

## Quick Start

Scan a GET parameter:

```bash
xpath -u "http://target.local/search?q=test" -p q
```

Scan all detected query parameters:

```bash
xpath -u "http://target.local/search?q=test&id=1"
```

Scan a POST body:

```bash
xpath -u "http://target.local/login" -m POST -d "user=*&pass=test"
```

Run all techniques and extract visible or blind data when possible:

```bash
xpath -u "http://target.local/search?q=test" -p q -t A -x
```

Use a proxy:

```bash
xpath -u "http://target.local/search?q=test" -p q --proxy http://127.0.0.1:8080
```

Save JSON output:

```bash
xpath -u "http://target.local/search?q=test" -p q -t A -o report.json -f json
```

## Usage

```text
USAGE
  xpath [OPTIONS] -u <URL>

TARGET
  -u, --url <URL>           Target URL
  -m, --method <METHOD>     HTTP method: GET or POST
  -d, --data <DATA>         POST body, use * to mark injection point
  -p, --param <PARAM>       Parameter(s) to test, comma-separated
  -c, --cookie <COOKIE>     Cookie string
  -H, --header <HEADER>     Extra header, repeatable

DETECTION
  -t, --technique <FLAGS>   E, B, T, U, P, or A
  -l, --level <1-5>         Payload thoroughness level
  -x, --extract             Extract data after confirming injection
      --xpath <EXPR>        XPath expression for extraction

OUTPUT
  -o, --output <FILE>       Save report
  -f, --format <FMT>        text or json
  -v, --verbose             Verbose output
```

## Techniques

### Error-Based

Sends malformed XPath payloads and detects framework-specific error signatures from Java, .NET, PHP, libxml2, Saxon, Xalan, and W3C XQuery error codes.

```bash
xpath -u "http://target.local/item?id=1" -p id -t E
```

### Boolean-Based Blind

Compares paired TRUE/FALSE payload responses using body similarity and size deltas. This is useful when results are not directly printed but application behavior changes.

```bash
xpath -u "http://target.local/search?q=test" -p q -t B
```

### Time-Based Blind

Uses computationally expensive XPath expressions to create measurable response-time differences when content-based signals are unavailable.

```bash
xpath -u "http://target.local/search?q=test" -p q -t T --time-sec 3
```

### Union / Node Selection

Tests whether a selector-like parameter can be unioned with absolute or relative XPath paths, such as `//text()`, `../../..//text()`, `//@*`, and indexed paths.

```bash
xpath -u "http://target.local/search?q=INVALID&field=name" -p field -t U -x
```

### Authentication Bypass

Checks predicate-breaking payloads, position-based payloads, role substring payloads, boolean functions, and context-aware bypass forms.

```bash
xpath -u "http://target.local/login" -m POST -d "username=*&password=test" -t P
```

## Extraction

When `-x` is enabled, `xpath` chooses the best available extraction mode:

| Mode | Description |
|---|---|
| Visible auth response | Parses new rows, links, redirects, and rendered values from successful bypass responses |
| Visible union paths | Extracts newly rendered text from union/node-selection payloads |
| Blind extraction | Uses `string-length()`, `substring()`, `name()`, and `count()` to infer XML data |

Example:

```bash
xpath -u "http://target.local/query?q=test" -p q -t A -x
```

Custom expression:

```bash
xpath -u "http://target.local/query?q=test" -p q -x --xpath "name(/*[1])"
```

## Payload Levels

| Level | Focus |
|---|---|
| `1` | Fast classic payloads |
| `2` | Common real-world predicate breaks |
| `3` | Default balanced scan |
| `4` | Encoded, entity, and path-breakout payloads |
| `5` | Maximum coverage and exotic variants |

## Build Targets

| Target | Output |
|---|---|
| `make linux` | `dist/xpath-linux-amd64` |
| `make windows` | `dist/xpath-windows-amd64.exe` |
| `make test` | Runs the Nim test suite |
| `make install` | Installs to `$(PREFIX)/bin/xpath` |
| `make deb` | `dist/xpath_1.0.0_amd64.deb` |
| `make clean` | Removes `build/` and `dist/` |

## Project Layout

```text
src/
  xpath.nim
  core/
    analyzer.nim
    crawler.nim
    extractor.nim
    http.nim
    payloads.nim
    reporter.nim
    scanner.nim
  utils/
    cli.nim
    config.nim
    logger.nim
```

## License

MIT License. See [LICENSE](LICENSE).

## Legal Notice

This tool is for authorized security testing only. Use it only on systems you own or have explicit written permission to test.
