rule EICAR_Test_File
{
    meta:
        description = "Тестовая сигнатура EICAR"
        author = "Glacier"
        severity = "high"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}
