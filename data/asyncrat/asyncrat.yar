rule AsyncRAT_Variant_Stub
{
    meta:
        description = "Detects AsyncRAT stub"
        author      = "rafosw"
        date        = "2026-03-29"
        threat      = "AsyncRAT"

    strings:
        $cfg_ports   = "%Ports%" ascii wide
        $cfg_hosts   = "%Hosts%" ascii wide
        $cfg_version = "%Version%" ascii wide
        $cfg_install = "%Install%" ascii wide
        $cfg_folder  = "%Folder%" ascii wide
        $cfg_mtx     = "%MTX%" ascii wide
        $cfg_cert    = "%Certificate%" ascii wide
        $cfg_anti    = "%Anti%" ascii wide
        $cfg_paste   = "%Pastebin%" ascii wide
        $cfg_bdos    = "%BDOS%" ascii wide

        $ns_client   = "Client.Connection" ascii wide
        $ns_install  = "Client.Install" ascii wide
        $ns_helper   = "Client.Helper" ascii wide
        $ns_packet   = "Client.Handle_Packet" ascii wide
        $ns_algo     = "Client.Algorithm" ascii wide
        $ns_anti     = "Anti_Analysis" ascii wide

        $anti_sandbox= "DetectSandboxie" ascii wide
        $anti_debug  = "DetectDebugger" ascii wide
        $anti_manu   = "DetectManufacturer" ascii wide
        $anti_disk   = "IsSmallDisk" ascii wide
        $run_anti    = "RunAntiAnalysis" ascii wide
        $sbie        = "SbieDll.dll" ascii wide
        $wmi_av      = "Select * from AntivirusProduct" ascii wide
        $wmi_sys     = "Select * from Win32_ComputerSystem" ascii wide

        $msgpack1    = "MessagePackLib.MessagePack" ascii wide
        $msgpack2    = "MsgPackEnum" ascii wide
        $keepalive   = "KeepAlivePacket" ascii wide
        $schtasks    = "/c schtasks /create /f /sc onlogon /rl highest /tn" ascii wide

    condition:
        uint16(0) == 0x5A4D 
        and (
            4 of ($cfg_*)
            and 2 of ($ns_*)
            and 3 of ($anti_*, $sbie, $wmi_av, $wmi_sys, $run_anti)
            and (any of ($msgpack*) or $keepalive or $schtasks)
        )
}
