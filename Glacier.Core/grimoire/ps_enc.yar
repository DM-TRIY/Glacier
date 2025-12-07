rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Base64-encoded PowerShell payload"
        author = "Glacier"
        severity = "high"

    strings:
        $ps1 = "powershell -enc" nocase
        $ps2 = "powershell.exe -enc" nocase

    condition:
        any of ($ps*)
}
