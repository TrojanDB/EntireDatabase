rule viralrat_Stub
{
    meta:
        description = "ViralRat stub dedection"
        author      = "rafosw"
        date        = "2026-03-11"
        threat      = "viralrat_stub"

    strings:
        $project_guid   = "{a59e18e9-fb69-4e5f-85cb-3462df212235}" ascii wide
        $build_id       = "635516223453928663" ascii wide

        $c2_endpoint    = "http://localhost:3030/Service.asmx" ascii wide
        $upload_func    = "UploadReport" ascii wide

        $res_a          = "MeuMVQhY" ascii wide
        $res_b          = "efdNnLWZ" ascii wide
        $res_c          = "IRdrDVOcD" ascii wide
        $res_d          = "LTjpQEJB" ascii wide

        $meta_a         = "BQgdFCFI" ascii wide
        $meta_b         = "MJIHZdPLu" ascii wide
        $meta_c         = "mwcenMWz" ascii wide
        $meta_d         = "jRQiwaMI" ascii wide
        $meta_e         = "fbzmiaeVy" ascii wide

        $co_stack       = "CO_StackFrameList" ascii wide
        $co_binary      = "CO_BinaryData" ascii wide
        $co_custom      = "CO_CustomData" ascii wide
        $co_filter      = "CO_FilterData" ascii wide
        $screenshot     = "Screenshot.png" ascii wide

        $encrypted_tag  = "_Encrypted$" ascii wide
        $crypto_helper  = "CryptoObfuscatorHelper" ascii wide

        $marker_jxps    = "jxPS" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and $encrypted_tag
        and $crypto_helper
        and ($project_guid or $build_id)
        and ($c2_endpoint or $upload_func)
        and 2 of ($res_a, $res_b, $res_c, $res_d)
        and 2 of ($meta_a, $meta_b, $meta_c, $meta_d, $meta_e)
        and 2 of ($co_stack, $co_binary, $co_custom, $co_filter, $screenshot)
        and $marker_jxps
}
