rule VenomRAT_Stub
{
    meta:
        description = "VenomRAT Client detection based on strings and structure"
        author      = "rafok2v9c"
        date        = "2026-03-27"
        threat      = "VenomRAT"
        reference   = "VenomRAT C2 client stub analysis"

    strings:
        $rat_name        = "VenomRAT" ascii wide
        $client_exe      = "Client.exe" ascii wide
        $rat_sig         = "Server_signa_ture" ascii wide
        $rat_cert        = "Server_Certificate" ascii wide
        $ns_connection   = "Client.Connection" ascii wide
        $ns_algorithm    = "Client.Algorithm" ascii wide
        $ns_install      = "Client.Install" ascii wide
        $ns_helper       = "Client.Helper" ascii wide
        $anti_analysis   = "Anti_Analysis" ascii wide
        $anti_process    = "Anti_Process" ascii wide
        $run_anti        = "RunAntiAnalysis" ascii wide
        $patch_etw       = "PatchETW" ascii wide
        $patch_amsi      = "Patcham_si" ascii wide
        $patch_mem       = "PatchMem" ascii wide
        $amsi_x64        = "x64_am_si_patch" ascii wide
        $amsi_x86        = "x86_am_si_patch" ascii wide
        $etw_x64         = "x64_etw_patch" ascii wide
        $etw_x86         = "x86_etw_patch" ascii wide
        $aes256          = "Aes256" ascii wide
        $hmacsha256      = "HMACSHA256" ascii wide
        $rfc_key         = "Rfc2898DeriveBytes" ascii wide
        $auth_key        = "_authKey" ascii wide
        $master_key      = "masterKey" ascii wide
        $pastebin        = "Paste_bin" ascii wide
        $ports           = "Por_ts" ascii wide
        $hosts           = "Hos_ts" ascii wide
        $keepalive       = "KeepAlivePacket" ascii wide
        $activate_ping   = "ActivatePo_ng" ascii wide
        $hvnc            = "Hvnc" ascii wide
        $hvnc_reply      = "HVNC_REPLY_MESSAGE" ascii wide
        $hvnc_bmp        = "HVNC_REPLY_BMP" ascii wide
        $stop_hvnc       = "StopHVNC" ascii wide
        $get_gpu         = "GetGPU" ascii wide
        $get_ram         = "GetRAM" ascii wide
        $get_cpu         = "GetCPUName" ascii wide
        $hwid            = "HwidGen" ascii wide
        $hw_id           = "Hw_id" ascii wide
        $wmi_cpu         = "Select * from Win32_Processor" ascii wide
        $wmi_sys         = "Select * From Win32_ComputerSystem" ascii wide
        $wmi_gpu         = "select * from Win32_VideoController" ascii wide
        $vm_check        = "isVM_by_wim_temper" ascii wide
        $tg_notify       = "TelegramNotify" ascii wide
        $hash1           = "D84F4C120005F1837DC65C04181F3DA9466B123FC369C359A301BABC12061570" ascii
        $hash2           = "E123F60E9FC6E974D1381F2F15FB19E7960628CC8925D65E344C2F2BDC64F424" ascii
        $hash3           = "CABAFE20CFEA6C92D3377C14650461E190857D48D13934B5562233C314AAFBB5" ascii

    condition:
        uint16(0) == 0x5A4D
        and 1 of ($rat_name, $rat_sig, $rat_cert, $client_exe)
        and 2 of ($ns_*)
        and 2 of ($anti_analysis, $anti_process, $run_anti, $patch_etw, $patch_amsi, $patch_mem)
        and 1 of ($amsi_x64, $amsi_x86, $etw_x64, $etw_x86)
        and ($aes256 or $hmacsha256)
        and ($rfc_key or $auth_key or $master_key)
        and 2 of ($pastebin, $ports, $hosts, $keepalive, $activate_ping)
        and 2 of ($get_gpu, $get_ram, $get_cpu, $hwid, $hw_id)
        and 1 of ($wmi_cpu, $wmi_sys, $wmi_gpu)
        and (
            2 of ($hvnc, $hvnc_reply, $hvnc_bmp, $stop_hvnc)
            or $tg_notify
            or $vm_check
            or 2 of ($hash1, $hash2, $hash3)
        )
}
