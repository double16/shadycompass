import json

from experta import Fact

from shadycompass.facts import FactReader, check_file_signature, TargetHostname, TargetIPv4Address, \
    HostnameIPv4Resolution, TargetIPv6Address, HostnameIPv6Resolution, HttpService, fact_reader_registry, \
    parse_products, Product, normalize_os_type


class NucleiJsonFactReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, '"matcher-name"'):
            return []
        print(f"[*] Reading nuclei findings from {file_path}")
        with open(file_path, 'rt') as f:
            data = json.load(f)
        if not isinstance(data, list):
            return []
        result = set()
        for record in data:
            record_type: str = record.get('type', None)
            hostname: str = record.get('host', None)
            port: str = record.get('port', None)
            addr: str = record.get('ip', None)

            if port:
                hostname = hostname.replace(f':{port}', '')

            if hostname:
                result.add(TargetHostname(hostname=hostname))
            if addr:
                if '.' in addr:
                    result.add(TargetIPv4Address(addr=addr))
                    if hostname:
                        result.add(HostnameIPv4Resolution(hostname=hostname, addr=addr))
                else:
                    result.add(TargetIPv6Address(addr=addr))
                    if hostname:
                        result.add(HostnameIPv6Resolution(hostname=hostname, addr=addr))
            else:
                continue

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
                pass

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
                    result.add(Product(product=parsed.get_product(), version=parsed.get_version(), **kwargs))

        return list(result)


fact_reader_registry.append(NucleiJsonFactReader())
