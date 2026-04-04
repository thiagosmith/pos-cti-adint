# Mapeamento de Infraestruturas Adversárias
- 02.1 Introdução ao Mapeamento de Infraestrutura
- 02.2 Técnicas de Fingerprinting de Infraestrutura (C2)
- 02.3 Ferramentas de OSINT
- 02.4 Análise de Certificados SSL, WHOIS e Histórico de DNS
- 02.5 Rastreamento de Infraestrutura C2
- 02.6 Análise de Tráfego Malicioso (PCAPs)
- 02.7 Estudo de Caso: Desmontando uma Rede de Bots

## Banner grabbing (ex: via curl, netcat, nmap)
### curl
```
curl -I http://scanme.org
```
### nmap
```
nmap -sV scanme.org -p 22,80
```
### NetCat
```
nc -v scanme.org 22
```
### FTP
```
ftp 122.28.45.37
```

## Ferramentas de OSINT
### DNSdumpster
Enumeração de subdomínios e visualização de registros DNS.

Link: https://dnsdumpster.com/

### crt.sh
Consulta de certificados SSL públicos. 

Link: https://crt.sh/

### Shodan
Busca por dispositivos conectados à internet e serviços expostos.

Link: https://www.shodan.io/

Operadores
```
hostname: busca site
country: busca país
os: busca sistema operacional
city: busca cidade
ip: busca por IP
geo: busca geolocalização
port: busca porta
org: busca organização
net: busca rede
"": algum termo
```

### Censys
Escaneamento global de serviços e certificados SSL. 

Link: https://search.censys.io/

Operadores
```
services.port: 21
location.country_code:BR AND services.port: 21
location.city: Rio-de-Janeiro
```

## Análise de Tráfego Malicioso (PCAPs)
Fontes de PCAPs reais: 
• Malware-Traffic-Analysis.net

https://www.malware-traffic-analysis.net/

• Contagio Malware Dump

https://contagiodump.blogspot.com/

• PacketTotal

https://lab.dynamite.ai/

• Any.Run (interativo, pode exportar PCAPs)

https://any.run/

### Estudo de caso prático PCAP: 
2023-AsyncRAT-infection.pcap (disponível em malware-traffic-analysis.net)

​https://www.malware-traffic-analysis.net/2023/10/23/2023-10-23-404TDS-Async-RAT-infection-traffic.pcap.zip

LUMMA STEALER INFECTION WITH FOLLOW-UP MALWARE 

https://www.malware-traffic-analysis.net/2025/09/24/2025-09-24-traffic-from-running-Setup.exe.pcap.zip

Análise automatizada

https://apackets.com/

## Estudo de Caso: Exploração de Apache e ransomware LockBit
Apache ActiveMQ Exploit Leads to LockBit Ransomware
The DFIR Report - February 23, 2026
https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/






