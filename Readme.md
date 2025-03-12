# Prometheus Security Toolkit

Um conjunto de ferramentas para análise de segurança de servidores Prometheus expostos.

## Ferramentas Incluídas

O toolkit contém as seguintes ferramentas:

### 1. Prometheus Massacre Ultimate

Ferramenta avançada para coleta e análise de dados de servidores Prometheus expostos.

#### Uso Básico

```bash
python prometheus_massacre_ultimate.py --url http://seu-prometheus:9090
```

#### Opções Completas

| Opção | Descrição |
|-------|-----------|
| `--url` | URL do Prometheus alvo (ex: http://192.168.100.1:9090) |
| `--stealth` | Modo stealth (1 req/seg) para evitar detecção |
| `--massacre` | Modo massacre (paralelismo máximo) para coleta agressiva |
| `--depth` | Profundidade de análise (1-5), onde 5 é a mais profunda |
| `--output` | Diretório de saída personalizado para os resultados |

#### Exemplos de Uso

Análise básica:
```bash
python prometheus_massacre_ultimate.py --url http://192.168.100.1:9090
```

Análise sigilosa:
```bash
python prometheus_massacre_ultimate.py --url http://192.168.100.1:9090 --stealth
```

Análise profunda e agressiva:
```bash
python prometheus_massacre_ultimate.py --url http://192.168.100.1:9090 --massacre --depth 5
```

Análise com diretório personalizado:
```bash
python prometheus_massacre_ultimate.py --url http://192.168.100.1:9090 --output prometheus_resultados
```

### 2. Verificador de Vulnerabilidade DoS

Ferramenta que verifica se uma instância Prometheus é vulnerável a ataques de negação de serviço.

#### Uso Básico

```bash
python prometheus_ddos_vulnerability_checker.py -u http://seu-prometheus:9090
```

#### Opções Completas

| Opção | Descrição |
|-------|-----------|
| `-u, --url` | URL do servidor Prometheus (obrigatório) |
| `-t, --timeout` | Timeout para requisições em segundos (padrão: 10) |
| `-c, --concurrency` | Número de testes concorrentes (padrão: 3) |
| `-p, --port-timeout` | Timeout para verificação de porta (padrão: 3.0) |
| `-v, --verbose` | Modo verboso com mais informações |
| `--no-banner` | Não mostrar o banner de início |
| `--no-color` | Desabilitar cores no output |
| `--log-file` | Arquivo para salvar logs (ex: prometheus_check.log) |
| `--username` | Usuário para autenticação básica |
| `--password` | Senha para autenticação básica |
| `--token` | Token de autenticação |
| `--ignore-ssl` | Ignorar verificação de certificados SSL |
| `--rate-limit-test` | Testar existência de rate limiting |
| `--output` | Arquivo de saída para o relatório JSON |

#### Exemplos de Uso

Verificação básica:
```bash
python prometheus_ddos_vulnerability_checker.py -u http://seu-prometheus:9090
```

Verificação com autenticação:
```bash
python prometheus_ddos_vulnerability_checker.py -u http://seu-prometheus:9090 --username admin --password senha
```

Verificação completa com teste de rate limiting:
```bash
python prometheus_ddos_vulnerability_checker.py -u http://seu-prometheus:9090 --rate-limit-test --verbose
```

### 3. Analisador de Dumps

Ferramenta para análise avançada de dumps de memória em busca de dados sensíveis.

#### Uso Básico

```bash
python dump_analise_advanced.py --dir diretorio_com_dumps
```

#### Opções Completas

| Opção | Descrição |
|-------|-----------|
| `--dir` | Diretório contendo os dumps (.dump, pprof) [Obrigatório] |
| `--add-pattern` | Adicionar padrão regex customizado para busca (pode ser usado múltiplas vezes) |

#### Exemplos de Uso

Análise básica de dumps:
```bash
python dump_analise_advanced.py --dir ./prometheus_massacre_20250310_123456
```

Análise com padrões personalizados:
```bash
python dump_analise_advanced.py --dir ./prometheus_massacre_20250310_123456 --add-pattern "senha: \S+" --add-pattern "api_token: \S+"
```

## O Que Cada Ferramenta Faz

### Prometheus Massacre Ultimate
Esta ferramenta coleta dados de um servidor Prometheus através de múltiplos endpoints, analisando as respostas em busca de informações sensíveis como:
- Credenciais e tokens de acesso
- Chaves de API e segredos
- IPs e hostnames internos
- URLs de serviços internos
- Configurações e detalhes da infraestrutura

A profundidade da análise define quanto a ferramenta vai explorar:
- **Nível 1**: Coleta básica de endpoints padrão
- **Nível 2-3**: Coleta endpoints e executa queries PromQL
- **Nível 4-5**: Análise completa com busca por outros serviços e exporters

### Verificador de Vulnerabilidade DoS
Esta ferramenta verifica se uma instância Prometheus é suscetível a ataques de negação de serviço, examinando:
- Endpoints vulneráveis que consomem muitos recursos (ex: heap profiling)
- Consultas PromQL potencialmente pesadas
- Exposição pública do servidor
- Implementação de rate limiting
- Vulnerabilidades em endpoints de federação

A ferramenta gera uma pontuação de risco de 0 a 10 e fornece recomendações específicas para mitigar as vulnerabilidades detectadas, sem realizar ataques reais ao alvo.

### Analisador de Dumps
Esta ferramenta examina arquivos de despejo de memória (.dump, pprof) extraídos durante um ataque ao Prometheus. Ela procura por:
- Chaves de API e tokens
- Senhas e credenciais
- E-mails e URLs
- Padrões personalizados definidos pelo usuário

## Instalação

```bash
# Clone este repositório
git clone https://github.com/seu-usuario/prometheus-security-toolkit.git
cd prometheus-security-toolkit

# Instale as dependências necessárias
pip install requests argparse concurrent.futures
```

## Resultados

### Prometheus Massacre Ultimate
A ferramenta cria um diretório com os seguintes resultados:
- Dumps de todos os endpoints acessados
- Arquivos com vazamentos marcados como "LEAKS_*"
- Análise dos resultados JSON
- Relatório final "_RELATORIO_FINAL.txt"

### Verificador de Vulnerabilidade DoS
A ferramenta gera:
- Relatório detalhado com índice de vulnerabilidade
- Lista de todos os endpoints vulneráveis
- Recomendações de segurança específicas
- Arquivo JSON com todos os resultados para análise posterior

### Analisador de Dumps
A ferramenta cria:
- Um subdiretório com timestamp dentro do diretório especificado
- Um arquivo JSON com todos os vazamentos encontrados

## Aviso de Segurança

⚠️ **IMPORTANTE**: Estas ferramentas devem ser usadas APENAS para fins educacionais, de pesquisa e em ambientes autorizados. O uso contra sistemas sem autorização expressa é ilegal e antiético.

## Uso Responsável

- Use somente em seus próprios sistemas ou com permissão explícita
- O modo stealth deve ser usado para minimizar o impacto nos sistemas
- Não compartilhe dados sensíveis obtidos das análises

## Licença

Este projeto é para fins educacionais e de pesquisa apenas. Use responsavelmente.
