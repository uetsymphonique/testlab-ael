"""Position-dependent XOR encoder for CertEnrollSvc.cs.

Usage:
    python encode.py "SeImpersonatePrivilege" _priv
    python encode.py "CreateNamedPipeW" _fn_cnpw
    python encode.py --dump                         # dump all current CertEnrollSvc entries
    python encode.py --verify                       # verify round-trip for all entries
"""
import sys

KEY_BASE = 0xA3
KEY_STEP = 0x5B

def key_at(i):
    return (KEY_BASE + i * KEY_STEP) & 0xFF

def encode_bytes(data):
    return [(b ^ key_at(i)) & 0xFF for i, b in enumerate(data)]

def decode_bytes(data):
    return [(b ^ key_at(i)) & 0xFF for i, b in enumerate(data)]

def encode_string(s):
    return encode_bytes(list(s.encode('utf-8')))

def decode_string(data):
    return bytes(decode_bytes(data)).decode('utf-8')

def fmt_csharp(encoded, var_name):
    h = ', '.join(f'0x{b:02x}' for b in encoded)
    return f'static readonly byte[] {var_name} = new byte[] {{ {h} }};'

# All strings currently in CertEnrollSvc.cs — keep in sync when adding new entries
REGISTRY = {
    '_priv': 'SeImpersonatePrivilege',
    '_desk': 'WinSta0\\Default',
    '_lpipe': '\\\\localhost/PIPE/',
    '_ep1': 'lsarpc',
    '_ep2': 'efsrpc',
    '_ep3': 'samr',
    '_ep4': 'lsass',
    '_ep5': 'netlogon',
    '_ncnp': 'ncacn_np',
    '_g1': 'c681d488-d850-11d0-8c52-00c04fd90f7e',
    '_g2': 'df1941c5-fe89-4e79-bf10-463657acf44d',
    '_lh': 'localhost',
    '_k32': 'kernel32.dll',
    '_adv': 'advapi32.dll',
    '_rpc': 'Rpcrt4.dll',
    '_fn_ll': 'LoadLibraryW',
    '_fn_gsh': 'GetStdHandle',
    '_fn_gft': 'GetFileType',
    '_fn_cfw': 'CreateFileW',
    '_fn_cnpw': 'CreateNamedPipeW',
    '_fn_cnp': 'ConnectNamedPipe',
    '_fn_inp': 'ImpersonateNamedPipeClient',
    '_fn_ch': 'CloseHandle',
    '_fn_atp': 'AdjustTokenPrivileges',
    '_fn_lpv': 'LookupPrivilegeValueW',
    '_fn_cp': 'CreatePipe',
    '_fn_cpau': 'CreateProcessAsUserW',
    '_fn_rbfsb': 'RpcBindingFromStringBindingW',
    '_fn_rbsai': 'RpcBindingSetAuthInfoW',
    '_fn_ncc2': 'NdrClientCall2',
    '_fn_rbf': 'RpcBindingFree',
    '_fn_rsbcw': 'RpcStringBindingComposeW',
    '_fn_rbso': 'RpcBindingSetOption',
}

def cmd_encode(plaintext, var_name):
    enc = encode_string(plaintext)
    print(fmt_csharp(enc, var_name))
    print(f'// plaintext: {plaintext}')
    print(f'// verify:    {decode_string(enc)}')

def cmd_dump():
    for var, plaintext in REGISTRY.items():
        print(fmt_csharp(encode_string(plaintext), var))
    print()
    print(f'// {len(REGISTRY)} entries')

def cmd_verify():
    ok = fail = 0
    for var, plaintext in REGISTRY.items():
        enc = encode_string(plaintext)
        dec = decode_string(enc)
        if dec == plaintext:
            ok += 1
        else:
            print(f'FAIL: {var} expected={plaintext!r} got={dec!r}')
            fail += 1
    print(f'{ok} OK, {fail} FAIL')

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--dump':
        cmd_dump()
    elif len(sys.argv) == 2 and sys.argv[1] == '--verify':
        cmd_verify()
    elif len(sys.argv) == 3:
        cmd_encode(sys.argv[1], sys.argv[2])
    else:
        print(__doc__)
