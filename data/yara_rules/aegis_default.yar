
rule Aegis_Suspicious_Strings
{
    meta:
        description = "Generic suspicious patterns"
        author = "AegisAV"
    strings:
        $a = "CreateRemoteThread" ascii wide
        $b = "VirtualAllocEx" ascii wide
        $c = "WriteProcessMemory" ascii wide
        $d = "powershell -enc" ascii wide nocase
        $e = "cmd.exe /c" ascii wide nocase
        $f = "This program cannot be run in DOS mode" ascii
    condition:
        2 of them
}

rule Aegis_EICAR
{
    meta:
        description = "EICAR test file"
    strings:
        $eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
