import json
import re

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, guess_target, TargetHostname, \
    ScanPresent, TargetDomain
from shadycompass.facts.services import create_service_facts

_DOMAIN_PATTERN = re.compile(r'\[\*]\s+(?:std|rvl|brt|srv|axfr|bing|yand|crt|snoop|tld|zonewalk):\s+.*:\s+(\S+)\.\.\.')
_DNS_LINE_PATTERN = re.compile(r'\s(A|[A-Z]{2,})\s+(\S+)\s+([0-9a-fA-F:./]+)', re.MULTILINE)
_SRV_LINE_PATTERN = re.compile(r'\sSRV\s+(\S+)\s+(\S+)\s+([0-9a-fA-F:./]+)\s+(\d+)', re.MULTILINE)


class DnsReconReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if check_file_signature(file_path, _DOMAIN_PATTERN, _DNS_LINE_PATTERN):
            return self._read_txt(file_path)
        if check_file_signature(file_path, '"type": "ScanInfo"'):
            return self._read_json(file_path)
        return []

    def _read_json(self, file_path: str) -> list[Fact]:
        result = []
        try:
            with open(file_path, 'rt') as f:
                data = json.load(f)
        except ValueError:
            return result
        if not isinstance(data, list):
            return result
        print(f"[*] Reading dnsrecon findings from {file_path}")
        targets = set()
        domains = set()
        resolutions = set()
        for record in data:
            record_type = record.get('type', None)
            addr = record.get('address', None)
            domain = record.get('domain', None)
            name = record.get('name', None)
            domains.add(TargetDomain(domain=domain))
            if record_type == 'SOA':
                hostname_args = dict()
                hostname = record.get('mname', None)
                target = guess_target(addr)
                targets.add(target)
                hostname_args['addr'] = addr
                if hostname:
                    hostname_args['hostname'] = hostname
                result.append(ScanPresent(category=ToolCategory.dns_scanner, name='dnsrecon',
                                          port=53,
                                          **hostname_args))
            elif record_type == 'SRV' and 'port' in record:
                service_fqdn = name
                hostname = record.get('target', None)
                port = int(record.get('port'))
                if '._udp.' in service_fqdn:
                    protocol = 'udp'
                else:
                    protocol = 'tcp'
                service_name = service_fqdn.split('.')[0].lstrip('_')
                create_service_facts([addr], None, port, protocol, result, False, service_name)

                if hostname:
                    target = guess_target(addr)
                    targets.add(target)
                    targets.add(TargetHostname(hostname=hostname))
                    resolutions.add(target.get_resolution(hostname, False))
            elif addr and domain and name:
                target = guess_target(addr)
                targets.add(target)
                targets.add(TargetHostname(hostname=name))
                resolutions.add(target.get_resolution(name, False))

        result.extend(targets)
        result.extend(resolutions)
        return result

    def _read_txt(self, file_path: str) -> list[Fact]:
        print(f"[*] Reading dnsrecon findings from {file_path}")
        targets = set()
        resolutions = set()
        result = []
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                m = _DOMAIN_PATTERN.search(line)
                if m:
                    hostname_args = dict()
                    target = guess_target(m.group(1))
                    targets.add(target)
                    if isinstance(target, TargetHostname):
                        hostname_args['hostname'] = target.get_hostname()
                    else:
                        hostname_args['addr'] = target.get_addr()
                    result.append(ScanPresent(category=ToolCategory.dns_scanner, name='dnsrecon',
                                              port=53,
                                              **hostname_args))
                    continue
                m = _SRV_LINE_PATTERN.search(line)
                if m:
                    service_fqdn = m.group(1)
                    # hostname = m.group(2)
                    addr = m.group(3)
                    port = int(m.group(4))
                    if '._udp.' in service_fqdn:
                        protocol = 'udp'
                    else:
                        protocol = 'tcp'
                    service_name = service_fqdn.split('.')[0].lstrip('_')
                    create_service_facts([addr], None, port, protocol, result, False, service_name)
                    continue
                m = _DNS_LINE_PATTERN.search(line)
                if m:
                    target = guess_target(m.group(3))
                    targets.add(target)
                    hostname = m.group(2)
                    targets.add(TargetHostname(hostname=hostname))
                    resolutions.add(target.get_resolution(hostname, False))
                    record_type = m.group(1)
                    if record_type == 'SOA':
                        hostname_args = dict()
                        hostname_args['hostname'] = hostname
                        if not isinstance(target, TargetHostname):
                            hostname_args['addr'] = target.get_addr()
                        result.append(ScanPresent(category=ToolCategory.dns_scanner, name='dnsrecon',
                                                  port=53,
                                                  **hostname_args))

        result.extend(targets)
        result.extend(resolutions)
        return result


fact_reader_registry.append(DnsReconReader())
