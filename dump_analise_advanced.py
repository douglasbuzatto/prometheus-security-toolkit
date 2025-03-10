import os
import re
import json
import argparse
from datetime import datetime

# ===============================
#         CONFIGURAÇÃO CLI
# ===============================

parser = argparse.ArgumentParser(description="Analisador Avançado de Dumps do Prometheus - By Boy Magia")
parser.add_argument("--dir", required=True, help="Diretório contendo os dumps (.dump, pprof)")
parser.add_argument("--add-pattern", action='append', help="Adicionar padrão regex customizado (ex.: --add-pattern 'senha: \\S+')")
args = parser.parse_args()

DUMPS_DIR = args.dir

# Criar pasta de saída com data/hora
NOW = datetime.now().strftime('%Y%m%d_%H%M%S')
EXPORT_DIR = os.path.join(DUMPS_DIR, f"leaks_export_{NOW}")
os.makedirs(EXPORT_DIR, exist_ok=True)
OUTPUT_FILE_JSON = os.path.join(EXPORT_DIR, f"LEAKS_EXPORT_{NOW}.json")

# ===============================
#     PADRÕES SENSÍVEIS
# ===============================

SENSITIVE_PATTERNS = [
    ("API Key", rb"(?i)(api[-_]?key\s*[:=]\s*[^\s;,}{]+)"),
    ("Secret", rb"(?i)(secret\s*[:=]\s*[^\s;,}{]+)"),
    ("Token", rb"(?i)(token\s*[:=]\s*[^\s;,}{]+)"),
    ("Password", rb"(?i)(password\s*[:=]\s*[^\s;,}{]+)"),
    ("AWS Key", rb"(?i)(AKIA[0-9A-Z]{16})"),
    ("JWT", rb"eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}"),
    ("Email", rb"(?i)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    ("URL", rb"https?://[^\s<>'\"]+"),
]

# Adicionar padrões customizados se passados por argumento
if args.add_pattern:
    for idx, pat in enumerate(args.add_pattern, start=1):
        SENSITIVE_PATTERNS.append((f"Custom_{idx}", pat.encode()))
        print(f"[+] Padrão customizado adicionado: {pat}")

# ===============================
#     FUNÇÕES PRINCIPAIS
# ===============================

def extract_strings_from_binary(file_path):
    """Extrai strings ASCII/Unicode visíveis"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            strings = re.findall(rb"[\x20-\x7E]{4,}", content)
        return [s.decode(errors='ignore') for s in strings]
    except Exception as e:
        print(f"[!] ERRO lendo {file_path}: {e}")
        return []

def search_sensitive_data(strings_list, file_name):
    """Busca dados sensíveis e retorna lista de achados"""
    findings = []
    for line in strings_list:
        for tag, pattern in SENSITIVE_PATTERNS:
            if re.search(pattern, line.encode()):
                findings.append({"tipo": tag, "valor": line.strip(), "origem": file_name})
                break  # Pega o primeiro match, evita duplicação
    return findings

# ===============================
#     EXECUÇÃO PRINCIPAL
# ===============================

def main():
    leaks_found = []
    print(f"[+] Iniciando análise de dumps em: {DUMPS_DIR}")
    print(f"[+] Resultados serão salvos em: {EXPORT_DIR}")

    for file in os.listdir(DUMPS_DIR):
        if file.endswith(".dump") or "pprof" in file:
            file_path = os.path.join(DUMPS_DIR, file)
            print(f"[+] Analisando {file}...")
            strings_list = extract_strings_from_binary(file_path)
            findings = search_sensitive_data(strings_list, file)
            leaks_found.extend(findings)
            print(f"[+] {len(findings)} vazamentos encontrados em {file}.")

    # Exportar para JSON
    with open(OUTPUT_FILE_JSON, 'w', encoding='utf-8') as jsonfile:
        json.dump(leaks_found, jsonfile, indent=2, ensure_ascii=False)
    print(f"\n[+] 🚨 Total de {len(leaks_found)} vazamentos encontrados.")
    print(f"[+] Arquivo JSON final salvo em: {OUTPUT_FILE_JSON}")
    print("[+] Análise finalizada com sucesso!")

if __name__ == "__main__":
    main()
