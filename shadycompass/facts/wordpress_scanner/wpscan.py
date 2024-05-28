import json
import urllib.parse

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, check_file_signature, fact_reader_registry, ScanPresent, Product, \
    guess_target, HttpService, \
    Username


class WpscanReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, '"description": "WordPress Security Scanner'):
            return []
        result = []
        try:
            with open(file_path, 'rt') as f:
                data = json.load(f)
        except ValueError:
            return result
        if not isinstance(data, dict):
            return result
        print(f"[*] Reading wpscan findings from {file_path}")

        scan_present_kwargs = {}

        target_url = data.get('target_url')
        if not target_url:
            return result
        target_parsed = urllib.parse.urlparse(target_url)
        target_fact = guess_target(target_parsed.hostname)
        scan_present_kwargs['url'] = target_url
        if 'hostname' in target_fact:
            scan_present_kwargs['hostname'] = target_fact.get('hostname')
        if 'addr' in target_fact:
            scan_present_kwargs['addr'] = target_fact.get('addr')
        if target_parsed.port:
            scan_present_kwargs['port'] = target_parsed.port
        else:
            scan_present_kwargs['port'] = 80
        if target_parsed.scheme.endswith('s'):
            secure = True
        else:
            secure = False

        target_ip = data.get('target_ip')
        if target_ip:
            scan_present_kwargs['addr'] = target_ip
            result.append(guess_target(target_ip))

        result.append(ScanPresent(category=ToolCategory.wordpress_scanner, name='wpscan', **scan_present_kwargs))

        if 'addr' in scan_present_kwargs and 'port' in scan_present_kwargs:
            result.append(
                HttpService(addr=scan_present_kwargs['addr'], port=scan_present_kwargs['port'], secure=secure))

            product_kwargs = {
                'product': 'wordpress',
                'addr': scan_present_kwargs['addr'],
                'port': scan_present_kwargs['port'],
                'secure': secure,
            }
            if data.get('version', {}).get('number', ''):
                product_kwargs['version'] = data.get('version', {}).get('number', '')
            if 'hostname' in scan_present_kwargs:
                product_kwargs['hostname'] = scan_present_kwargs['hostname']
            result.append(Product(**product_kwargs))

        user_kwargs = {
            'addr': scan_present_kwargs['addr'],
        }
        if 'hostname' in scan_present_kwargs:
            user_kwargs['hostname'] = scan_present_kwargs['hostname']
        for user in data.get('users', {}).keys():
            result.append(Username(username=user, **user_kwargs))

        return result


fact_reader_registry.append(WpscanReader())
