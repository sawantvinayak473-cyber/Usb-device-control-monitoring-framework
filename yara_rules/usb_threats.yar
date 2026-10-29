/* USB Security Framework -- baseline USB file threat rules. */

rule PE_Executable
{
    meta:
        description = "Windows PE executable content"
        severity = "HIGH"
        category = "executable"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe
}

rule AutoRun_Infection
{
    meta:
        description = "Autorun infection vector"
        severity = "CRITICAL"
        category = "autorun"
    strings:
        $autorun = "[AutoRun]" nocase
        $open = "open=" nocase
        $shellexec = "ShellExecute=" nocase
    condition:
        ($autorun and $open) or ($autorun and $shellexec)
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download and execution indicators"
        severity = "CRITICAL"
        category = "powershell"
    strings:
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "WebClient" nocase
        $iex = "Invoke-Expression" nocase
        $iex_short = "IEX" nocase
        $encoded = "-EncodedCommand" nocase
        $bypass = "bypass" nocase
    condition:
        2 of ($dl1, $dl2, $dl3) or (($iex or $iex_short) and ($dl1 or $dl2)) or ($encoded and $bypass)
}

rule Reverse_Shell_Indicators
{
    meta:
        description = "Common reverse shell indicators"
        severity = "CRITICAL"
        category = "reverse_shell"
    strings:
        $nc = "nc.exe" nocase
        $ncat = "ncat" nocase
        $tcp = "TCPClient" nocase
        $stream = "NetworkStream" nocase
        $reader = "StreamReader" nocase
        $socket = "socket.connect" nocase
        $bash = "/bin/bash" nocase
        $sh = "/bin/sh" nocase
    condition:
        $nc or $ncat or all of ($tcp, $stream, $reader) or ($socket and ($bash or $sh))
}

rule Suspicious_Batch_Script
{
    meta:
        description = "Batch persistence or credential-discovery indicators"
        severity = "HIGH"
        category = "batch"
    strings:
        $reg = "reg add" nocase
        $run = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $net_user = "net user" nocase
        $net_group = "net localgroup" nocase
        $service = "sc create" nocase
        $task = "schtasks /create" nocase
    condition:
        ($reg and $run) or $service or $task or ($net_user and $net_group)
}

rule Encoded_Payload
{
    meta:
        description = "Base64-encoded or obfuscated payload"
        severity = "HIGH"
        category = "obfuscation"
    strings:
        $base64 = /[A-Za-z0-9+\/]{40,}={0,2}/
        $frombase = "FromBase64String" nocase
        $convert = "[Convert]::" nocase
    condition:
        ($frombase or $convert) and $base64
}
