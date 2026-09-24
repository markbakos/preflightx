rule PF_Encoded_PowerShell_Download_Execute {
    meta:
        family = "generic-stager"
    strings:
        $download = "DownloadString" nocase
        $decode = "FromBase64String" nocase
        $execute = "Invoke-Expression" nocase
    condition:
        all of them
}

rule PF_Aes_Encrypted_Function_Loader {
    meta:
        family = "generic-loader"
    strings:
        $decrypt = "createDecipheriv" nocase
        $cipher = "aes-256-cbc" nocase
        $execute = /new\s+Function/ nocase
    condition:
        all of them
}
