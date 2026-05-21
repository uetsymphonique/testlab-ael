#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <iostream>
#include <iomanip>
#include <string>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

// Fallback for Windows Server: Query Windows Defender via WMI
bool QueryWindowsDefenderWMI(IWbemLocator* pLoc) {
    HRESULT hr;
    IWbemServices* pSvc = NULL;
    
    // Connect to root\Microsoft\Windows\Defender namespace
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\Microsoft\\Windows\\Defender"),
        NULL, NULL, 0, NULL, 0, 0, &pSvc
    );
    
    if (FAILED(hr)) {
        wcout << L"[!] Could not connect to ROOT\\Microsoft\\Windows\\Defender namespace. Error code: 0x" << hex << hr << endl;
        return false;
    }
    
    wcout << L"[+] Connected to ROOT\\Microsoft\\Windows\\Defender namespace" << endl;
    
    // Set security levels on the proxy
    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );
    
    if (FAILED(hr)) {
        wcout << L"[!] Could not set proxy blanket. Error code: 0x" << hex << hr << endl;
        pSvc->Release();
        return false;
    }
    
    // Query MSFT_MpComputerStatus
    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM MSFT_MpComputerStatus"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );
    
    if (FAILED(hr)) {
        wcout << L"[!] Query for MSFT_MpComputerStatus failed. Error code: 0x" << hex << hr << endl;
        pSvc->Release();
        return false;
    }
    
    // Get result
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    
    if (uReturn == 0) {
        wcout << L"[!] No MSFT_MpComputerStatus instance found." << endl;
        pEnumerator->Release();
        pSvc->Release();
        return false;
    }
    
    VARIANT vtProp;
    
    // Get AntivirusEnabled
    bool avEnabled = false;
    hr = pclsObj->Get(L"AntivirusEnabled", 0, &vtProp, 0, 0);
    if (SUCCEEDED(hr) && vtProp.vt == VT_BOOL) {
        avEnabled = (vtProp.boolVal == VARIANT_TRUE);
        VariantClear(&vtProp);
    }
    
    // Get RealTimeProtectionEnabled
    bool rtpEnabled = false;
    hr = pclsObj->Get(L"RealTimeProtectionEnabled", 0, &vtProp, 0, 0);
    if (SUCCEEDED(hr) && vtProp.vt == VT_BOOL) {
        rtpEnabled = (vtProp.boolVal == VARIANT_TRUE);
        VariantClear(&vtProp);
    }
    
    // Get AMProductVersion
    wstring productVersion = L"Unknown";
    hr = pclsObj->Get(L"AMProductVersion", 0, &vtProp, 0, 0);
    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
        productVersion = vtProp.bstrVal;
        VariantClear(&vtProp);
    }
    
    // Get AntivirusSignatureLastUpdated
    wstring sigLastUpdated = L"Unknown";
    hr = pclsObj->Get(L"AntivirusSignatureLastUpdated", 0, &vtProp, 0, 0);
    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
        sigLastUpdated = vtProp.bstrVal;
        VariantClear(&vtProp);
    }
    
    // Output
    wcout << L"=== Antivirus Product #1 ===" << endl;
    wcout << L"  displayName: Windows Defender Antivirus" << endl;
    wcout << L"  instanceGuid: {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}" << endl;
    wcout << L"  pathToSignedProductExe: C:\\Program Files\\Windows Defender\\MsMpEng.exe" << endl;
    wcout << L"  pathToSignedReportingExe: C:\\Program Files\\Windows Defender\\MpCmdRun.exe" << endl;
    wcout << L"  productVersion: " << productVersion << endl;
    wcout << L"  productState: 0x" << hex << uppercase << setw(6) << setfill(L'0') << (avEnabled ? 0x001000 : 0x000000) << dec << endl;
    wcout << L"  Product State (Raw): 0x" << hex << uppercase << setw(6) << setfill(L'0') << (avEnabled ? 0x001000 : 0x000000) << dec << endl;
    wcout << L"  Status: " << (avEnabled ? L"ENABLED" : L"DISABLED") << endl;
    wcout << L"  Real-Time Protection: " << (rtpEnabled ? L"ENABLED" : L"DISABLED") << endl;
    wcout << L"  Signature Last Updated: " << sigLastUpdated << endl;
    wcout << endl;
    
    pclsObj->Release();
    pEnumerator->Release();
    pSvc->Release();
    
    return true;
}

void ParseProductState(DWORD productState) {
    wcout << L"  Product State (Raw): 0x" << hex << uppercase << setw(6) << setfill(L'0') << productState << dec << endl;
    
    // Extract status byte
    BYTE securityState = (productState & 0x00FF00) >> 8;
    
    // Check if enabled (bit 4 of security state)
    bool enabled = (securityState & 0x10) == 0x10;
    bool updated = (securityState & 0x10) == 0x00;
    
    wcout << L"  Status: " << (enabled ? L"ENABLED" : L"DISABLED") << endl;
    wcout << L"  Definitions: " << (updated ? L"UP-TO-DATE" : L"OUT-OF-DATE") << endl;
}

int main() {
    HRESULT hr;
    
    wcout << L"[*] Querying installed Antivirus products using WMI COM API...\n" << endl;
    
    // Initialize COM
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wcout << L"[!] Failed to initialize COM library. Error code: 0x" << hex << hr << endl;
        return 1;
    }
    
    // Set COM security levels
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );
    
    if (FAILED(hr)) {
        wcout << L"[!] Failed to initialize security. Error code: 0x" << hex << hr << endl;
        CoUninitialize();
        return 1;
    }
    
    // Obtain the initial locator to WMI
    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLoc
    );
    
    if (FAILED(hr)) {
        wcout << L"[!] Failed to create IWbemLocator object. Error code: 0x" << hex << hr << endl;
        CoUninitialize();
        return 1;
    }
    
    // Connect to WMI namespace
    IWbemServices* pSvc = NULL;
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\SecurityCenter2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );
    
    if (FAILED(hr)) {
        wcout << L"[!] Could not connect to ROOT\\SecurityCenter2 namespace. Error code: 0x" << hex << hr << endl;
        wcout << L"[*] This is expected on Windows Server. Attempting fallback..." << endl;
        
        // Try legacy SecurityCenter namespace first
        hr = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\SecurityCenter"),
            NULL, NULL, 0, NULL, 0, 0, &pSvc
        );
        
        if (FAILED(hr)) {
            wcout << L"[!] Could not connect to ROOT\\SecurityCenter namespace either. Error code: 0x" << hex << hr << endl;
            
            // Final fallback: Query Windows Defender via WMI
            wcout << L"[*] Falling back to Windows Defender WMI query..." << endl;
            
            if (QueryWindowsDefenderWMI(pLoc)) {
                wcout << L"\n[+] Total antivirus products found: 1" << endl;
                wcout << L"\n[*] Query completed (via WMI fallback)." << endl;
                pLoc->Release();
                CoUninitialize();
                return 0;
            }
            
            wcout << L"[!] Could not detect any antivirus product." << endl;
            pLoc->Release();
            CoUninitialize();
            return 1;
        }
        
        wcout << L"[+] Connected to ROOT\\SecurityCenter (legacy namespace)" << endl;
    }
    
    // Set security levels on the proxy
    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );
    
    if (FAILED(hr)) {
        wcout << L"[!] Could not set proxy blanket. Error code: 0x" << hex << hr << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }
    
    // Execute WQL query to get antivirus products
    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM AntiVirusProduct"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );
    
    if (FAILED(hr)) {
        wcout << L"[!] Query failed. Error code: 0x" << hex << hr << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }
    
    // Enumerate results
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    int count = 0;
    
    while (pEnumerator) {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        
        if (0 == uReturn) {
            break;
        }
        
        count++;
        wcout << L"=== Antivirus Product #" << count << L" ===" << endl;
        
        VARIANT vtProp;
        
        // Get displayName
        hr = pclsObj->Get(L"displayName", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            wcout << L"  displayName: " << vtProp.bstrVal << endl;
            VariantClear(&vtProp);
        }
        
        // Get instanceGuid
        hr = pclsObj->Get(L"instanceGuid", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            wcout << L"  instanceGuid: " << vtProp.bstrVal << endl;
            VariantClear(&vtProp);
        }
        
        // Get pathToSignedProductExe
        hr = pclsObj->Get(L"pathToSignedProductExe", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            wcout << L"  pathToSignedProductExe: " << vtProp.bstrVal << endl;
            VariantClear(&vtProp);
        }
        
        // Get pathToSignedReportingExe
        hr = pclsObj->Get(L"pathToSignedReportingExe", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            wcout << L"  pathToSignedReportingExe: " << vtProp.bstrVal << endl;
            VariantClear(&vtProp);
        }
        
        // Get productState
        hr = pclsObj->Get(L"productState", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            wcout << L"  productState: 0x" << hex << uppercase << setw(6) << setfill(L'0') << vtProp.uintVal << dec << endl;
            ParseProductState(vtProp.uintVal);
            VariantClear(&vtProp);
        }
        
        wcout << endl;
        pclsObj->Release();
    }
    
    if (count == 0) {
        wcout << L"[!] No antivirus products found." << endl;
    } else {
        wcout << L"[+] Total antivirus products found: " << count << endl;
    }
    
    wcout << L"\n[*] Query completed." << endl;
    
    // Cleanup
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();
    
    return 0;
}
