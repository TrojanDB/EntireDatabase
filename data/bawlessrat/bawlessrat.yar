rule Bawless_RAT_Stub
{
    meta:
        description = "Detects Bawless RAT stub"
        author      = "rafosw"
        date        = "2026-03-29"
        threat      = "BawlessRAT"

    strings:
        $c1 = "%Ports%" ascii wide
        $c2 = "%Hosts%" ascii wide
        $c3 = "%MTX%" ascii wide
        $c4 = "%Certificate%" ascii wide
        $c5 = "%Version%" ascii wide

        $f1 = "bawless-client" ascii wide
        $f2 = "DcRatByqwqdanchun" ascii wide
        $f3 = "Client.exe" ascii wide

        $n1 = "Client.Connection" ascii wide
        $n2 = "Client.Install" ascii wide
        $n3 = "Client.Handle_Packet" ascii wide
        $n4 = "Anti_Analysis" ascii wide

        $m1 = "Patcham_si" ascii wide
        $m2 = "PatchETW" ascii wide
        $m3 = "RtlSetProcessIsCritical" ascii wide
        $m4 = "schtasks /create /f /sc onlogon" ascii wide
        $m5 = "costura.metadata" ascii wide

        $s1 = "MessagePackLib.MessagePack" ascii wide
        $s2 = "KeepAlivePacket" ascii wide

    condition:
        uint16(0) == 0x5A4D 
        and (
            2 of ($c*) 
            or (1 of ($n*) and 1 of ($m*))
            or (1 of ($f*))
            or (all of ($s*))
        )
}
