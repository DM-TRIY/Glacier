rule UPX_Packed_File
{
    meta:
        description = "Detects UPX-packed executables"
        author = "Glacier"
        severity = "medium"

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii

    condition:
        any of ($upx*)
}
