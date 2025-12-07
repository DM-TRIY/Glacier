rule Autorun_Persistence_Reg
{
    meta:
        description = "Detects registry autorun persistence entries"
        author = "Glacier"
        severity = "medium"

    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

    condition:
        any of ($run*)
}
