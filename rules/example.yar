// Example YARA rules. Use with: wedontlikeit scan --yara rules/ <target>
// Set `severity` in meta to "high", "medium" or "low" (default: high).

rule Script_Download_And_Run
{
    meta:
        description = "Shell script that downloads something and pipes it straight into a shell"
        severity = "medium"
    strings:
        $a = /(curl|wget)[^\n|]{1,200}\|\s*(ba|z)?sh/
    condition:
        filesize < 1MB and $a
}

rule Crypto_Miner
{
    meta:
        description = "Signs of a cryptocurrency miner (XMRig and friends)"
        severity = "medium"
    strings:
        $s1 = /stratum\+tcp:\/\// ascii
        $s2 = "xmrig" ascii nocase
        $s3 = "--donate-level" ascii
    condition:
        2 of them
}
