rule iRaQRAT_Stub
{
    meta:
        description = "IraqRAT Stub detection"
        author      = "rafok2v9c"
        date        = "2026-03-06"
        threat      = "IraqRAT"
    strings:
        $splitter      = "nj-q8" ascii wide
        $separator     = "|BawaneH|" ascii wide
        $pdb           = "iRaQ RAT" ascii wide
        $persistence   = "\\Microsoft\\svchost.exe" ascii wide
        $regrun        = "software\\microsoft\\windows\\currentversion\\run" ascii wide
        $cmd_uninstall = "Uninstall" ascii wide
        $cmd_keylog    = "getlog" ascii wide
        $cmd_shutdown  = "shutdown -s -t 00" ascii wide
        $cmd_processes = "GetProcesses" ascii wide
        $sql_chrome    = "SELECT * FROM moz_logins" ascii wide
        $sql_master    = "sqlite_master" ascii wide
        $chrome_path   = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and ($splitter or $pdb)
        and $separator
        and 2 of ($cmd_*)
        and 1 of ($sql_chrome, $sql_master, $chrome_path)
        and ($persistence or $regrun)
}
