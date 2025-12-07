import "pe"

rule PE_File_Generic
{
    meta:
        description = "PE32 / PE64 executable detector"
        author = "Glacier"
        severity = "medium"

    condition:
        pe.is_pe
}
