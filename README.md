# JoomHound 🦁

Uma ferramenta de enumeração e brute-force de Joomla de última geração, combinando o melhor de `droopescan`, `JoomlaScan` e `joomscan` (OWASP).

## Features

- ✅ Detecção de versão de Joomla
- ✅ Enumeração de componentes ativos
- ✅ Enumeração de templates
- ✅ Brute-force de usuários
- ✅ Brute-force de senhas (com rate limiting inteligente)
- ✅ Scanning de vulnerabilidades conhecidas (CVE integration)
- ✅ Multi-threading otimizado
- ✅ Suporte a proxy SOCKS5 e HTTP
- ✅ Output em JSON/XML/Markdown

## Instalação

```bash
go get -u github.com/lfgrillo83/joomhound
go install github.com/lfgrillo83/joomhound@latest
```

## Uso Rápido

```bash
# Enumeração básica
joomhound enum -t https://target.com

# Brute-force de usuários
joomhound brute -t https://target.com --users users.txt

# Brute-force de senhas
joomhound brute -t https://target.com -u admin --passwords rockyou.txt

# Scan completo
joomhound scan -t https://target.com -o report.json
```

## Estrutura

```
├── cmd/
│   └── joomhound/
│       └── main.go
├── internal/
│   ├── enum/        # Enumeração de versão, componentes
│   ├── bruteforce/  # Brute-force de usuários e senhas
│   ├── cve/         # Integração com CVE
│   ├── http/        # Cliente HTTP com proxy, rate limiting
│   └── output/      # Formatação de saída
├── go.mod
├── go.sum
└── README.md
```

## Roadmap

- [ ] Detecção de versão avançada
- [ ] Enumeração de plugins
- [ ] Enumeração de templates
- [ ] Brute-force distribuído
- [ ] WebSocket para updates em tempo real
- [ ] Integração com database de CVEs
- [ ] Dashboard web interativo
