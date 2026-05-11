## XPath Injection Scanner - Advanced vulnerability detection tool.
## Coded by Chokri Hammedi (blue0x1).
## Licensed under the MIT License.
## Legal use only: use on systems you own or have explicit permission to test.

import times, terminal, strutils

type
  LogLevel* = enum
    lvlDebug   = 0
    lvlInfo    = 1
    lvlSuccess = 2
    lvlWarn    = 3
    lvlError   = 4
    lvlCritical = 5

var
  gVerbose*  = false
  gNoColor*  = false
  gLogLevel* = lvlInfo

const
  cReset = "\e[0m"
  cPink = "\e[38;2;255;82;168m"
  cRose = "\e[38;2;231;36;113m"
  cLilac = "\e[38;2;178;112;255m"
  cSoft = "\e[38;2;255;228;240m"
  cPeach = "\e[38;2;255;156;117m"
  cText = "\e[38;2;245;238;246m"
  cDim = "\e[38;2;180;119;150m"
  cFoundBg = "\e[48;2;92;12;48m"

proc ts(): string =
  now().format("HH:mm:ss")

proc colorPrint(fg: ForegroundColor, bright: bool, prefix, msg: string) =
  if gNoColor:
    echo prefix & " " & msg
  else:
    let color =
      case fg
      of fgRed: cRose
      of fgYellow: cPeach
      of fgBlue, fgCyan: cLilac
      of fgGreen: cPink
      else: cSoft
    if fg == fgGreen:
      stdout.write(cFoundBg & cPink & prefix & cReset & " " & cPink & msg & cReset & "\n")
    else:
      stdout.write(color & prefix & cReset & " " & cText & msg & cReset & "\n")
  stdout.flushFile()

proc debug*(msg: string) =
  if gVerbose and gLogLevel <= lvlDebug:
    colorPrint(fgCyan, false, "[" & ts() & "][DBG]", msg)

proc info*(msg: string) =
  if gLogLevel <= lvlInfo:
    colorPrint(fgBlue, false, "[" & ts() & "][INF]", msg)

proc success*(msg: string) =
  if gLogLevel <= lvlSuccess:
    colorPrint(fgGreen, true, "[" & ts() & "][ * ]", msg)

proc warn*(msg: string) =
  if gLogLevel <= lvlWarn:
    colorPrint(fgYellow, true, "[" & ts() & "][ ! ]", msg)

proc error*(msg: string) =
  if gLogLevel <= lvlError:
    colorPrint(fgRed, false, "[" & ts() & "][ ✗ ]", msg)

proc critical*(msg: string) =
  colorPrint(fgRed, true, "[" & ts() & "][!!!]", msg)

proc finding*(label, value: string) =
  if gNoColor:
    echo "  [+] " & label & ": " & value
  else:
    stdout.write(cFoundBg & cPink & "  [>] " & cReset & cSoft & label & cReset &
                 cDim & ": " & cReset & cText & value & cReset & "\n")
  stdout.flushFile()

proc banner*() =
  let art = """
  ============================================================
      __   ______   ___   ______ __  __
      \ \ / / __ \ /   | /_  __// / / /
       \ V / /_/ // /| |  / /  / /_/ /
       /   / ____// ___ | / /  / __  /
      /_/|_/_/    /_/  |_|/_/  /_/ /_/

         [ XPATH INJECTION SCANNER ]
             v1.0.0 | chokri hammedi (blue0x1)
  ============================================================
  """
  if gNoColor:
    echo art
    echo "  XPath Injection Scanner v1.0.0  by chokri hammedi (blue0x1)"
    echo "  Techniques: Error | Boolean | Blind | Union"
    echo "  Legal Notice: use only on systems you own or have explicit permission to test."
    echo "  " & "-".repeat(58)
  else:
    stdout.write(cDim & "  ============================================================\n" & cReset)
    stdout.write(cRose & "      __   " & cPink & "______   ___   ______ __  __\n" & cReset)
    stdout.write(cRose & "      \\ \\ / / " & cPink & "__ \\ /   | /_  __// / / /\n" & cReset)
    stdout.write(cRose & "       \\ V / " & cPink & "/_/ // /| |  / /  / /_/ /\n" & cReset)
    stdout.write(cRose & "       /   / " & cPink & "____// ___ | / /  / __  /\n" & cReset)
    stdout.write(cRose & "      /_/|_/" & cPink & "_/    /_/  |_|/_/  /_/ /_/\n\n" & cReset)
    stdout.write(cPink & "         [ " & cRose & "X" & cPink & "PATH INJECTION SCANNER ]\n" & cReset)
    stdout.write(cLilac & "             v1.0.0 | chokri hammedi (blue0x1)\n" & cReset)
    stdout.write(cDim & "  ============================================================\n" & cReset)
    stdout.write(cSoft & "  XPath Injection Scanner v1.0.0" & cReset &
                 cLilac & "  by chokri hammedi (blue0x1)\n" & cReset)
    stdout.write(cPeach & "  Techniques: Error | Boolean | Blind | Union\n" & cReset)
    stdout.write(cRose & "  Legal Notice: use only on systems you own or have explicit permission to test.\n" & cReset)
    stdout.write(cDim & "  " & "-".repeat(58) & "\n" & cReset)
  echo ""
