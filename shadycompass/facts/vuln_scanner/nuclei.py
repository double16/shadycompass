import json

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, check_file_signature, TargetIPv4Address, \
    HostnameIPv4Resolution, TargetIPv6Address, HostnameIPv6Resolution, HttpService, fact_reader_registry, \
    parse_products, Product, normalize_os_type, ScanPresent, guess_target, WindowsDomain, CVE
from shadycompass.facts.services import create_service_facts
from shadycompass.rules.vuln_scanner.nuclei import NucleiRules


class NucleiJsonFactReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, '"template-id"'):
            return []
        try:
            with open(file_path, 'rt') as f:
                data = json.load(f)
        except ValueError:
            return []
        if not isinstance(data, list):
            return []
        print(f"[*] Reading nuclei findings from {file_path}")
        result = set()
        for record in data:
            record_type: str = record.get('type', None)
            hostname: str = record.get('host', None)
            port: str = record.get('port', None)
            addr: str = record.get('ip', None)

            if port:
                hostname = hostname.replace(f':{port}', '')

            if hostname:
                result.add(guess_target(hostname))
            if addr:
                result.add(ScanPresent(category=ToolCategory.vuln_scanner, name=NucleiRules.nuclei_tool_name, addr=addr))
                if '.' in addr:
                    result.add(TargetIPv4Address(addr=addr))
                    if hostname and hostname != addr:
                        result.add(HostnameIPv4Resolution(hostname=hostname, addr=addr, implied=True))
                else:
                    result.add(TargetIPv6Address(addr=addr))
                    if hostname and hostname != addr:
                        result.add(HostnameIPv6Resolution(hostname=hostname, addr=addr, implied=True))
            else:
                continue

            products: list[Product] = []
            if 'tech' in record.get('info', {}).get('tags', {}) and 'extracted-results' in record:
                extracted = record.get('extracted-results', '')
                if isinstance(extracted, list):
                    extracted = ' '.join(extracted)
                os_type = normalize_os_type(extracted)
                kwargs = {'addr': addr, 'port': int(port)}
                if hostname:
                    kwargs['hostname'] = hostname
                if os_type:
                    kwargs['os_type'] = os_type
                for parsed in parse_products(extracted):
                    product = Product(product=parsed.get_product(), version=parsed.get_version(), **kwargs)
                    products.append(product)
                    result.add(product)

            if record_type == 'http':
                secure = False
                scheme = record.get('scheme', None)
                if scheme and 'https' in scheme:
                    secure = True
                url = record.get('url', None)
                if url and 'https' in url:
                    secure = True
                result.add(HttpService(addr=addr, port=int(port), secure=secure))
            elif record_type == 'tcp':
                service_name = 'unknown'
                metadata = record.get('info', {}).get('metadata', {})
                if 'censys-query' in metadata:
                    service_name = str(metadata['censys-query']).replace('services.service_name:', '').lower()
                elif 'shodan-query' in metadata:
                    service_name = str(metadata['shodan-query']).lower()
                elif 'tags' in record.get('info', {}):
                    tags: list[str] = list(record.get('info', {}).get('tags')).copy()
                    for common_tag in ['detect', 'network', 'seclists', 'windows', 'linux', 'mac']:
                        try:
                            tags.remove(common_tag)
                        except ValueError:
                            pass
                    if tags:
                        service_name = tags[0]

                services = []
                create_service_facts([addr], None, int(port), 'tcp', services, False, service_name, products)
                for service in services:
                    result.add(service)

            if 'cve-id' in record.get('info', {}).get('classification', {}):
                cve_kwargs = {}
                if hostname:
                    cve_kwargs['hostname'] = hostname
                if addr:
                    cve_kwargs['addr'] = addr
                if port:
                    cve_kwargs['port'] = int(port)
                for cve_id in (record.get('info', {}).get('classification', {}).get('cve-id', []) or []):
                    result.add(CVE(cve=cve_id, **cve_kwargs))

            if 'smb' in record.get('info', {}).get('tags', {}) and 'extracted-results' in record:
                extracted = record.get('extracted-results', '')
                if isinstance(extracted, list):
                    data = dict()
                    for line in extracted:
                        split = line.split(':', 1)
                        if len(split) == 2:
                            data[split[0].strip()] = split[1].strip()
                    if 'NetBIOSDomainName' in data:
                        kwargs = {'netbios_domain_name': data['NetBIOSDomainName']}
                        if 'ForestName' in data:
                            kwargs['dns_domain_name'] = data['ForestName']
                            kwargs['dns_tree_name'] = data['ForestName']
                        result.add(WindowsDomain(**kwargs))

        return list(result)


fact_reader_registry.append(NucleiJsonFactReader())
