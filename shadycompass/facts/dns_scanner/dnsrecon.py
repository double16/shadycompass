import re

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, guess_target, TargetHostname, \
    TargetIPv4Address, HostnameIPv4Resolution, TargetIPv6Address, HostnameIPv6Resolution, ScanPresent
from shadycompass.facts.services import create_service_facts

_DOMAIN_PATTERN = re.compile(r'std:\s+.*:\s+(\S+)\.\.\.')
_DNS_LINE_PATTERN = re.compile(r'\s(A|[A-Z]{2,})\s+(\S+)\s+([0-9a-fA-F:./]+)', re.MULTILINE)
_SRV_LINE_PATTERN = re.compile(r'\sSRV\s+(\S+)\s+(\S+)\s+([0-9a-fA-F:./]+)\s+(\d+)', re.MULTILINE)


class DnsReconReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, _DOMAIN_PATTERN, _DNS_LINE_PATTERN):
            return []
        print(f"[*] Reading dnsrecon findings from {file_path}")
        targets = set()
        resolutions = set()
        services = set()
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
                    if '._tcp.' in service_fqdn:
                        protocol = 'tcp'
                    elif '._udp.' in service_fqdn:
                        protocol = 'udp'
                    service_name = service_fqdn.split('.')[0].lstrip('_')
                    create_service_facts([addr], None, port, protocol, result, False, service_name)
                    continue
                m = _DNS_LINE_PATTERN.search(line)
                if m:
                    target = guess_target(m.group(3))
                    targets.add(target)
                    hostname = m.group(2)
                    targets.add(TargetHostname(hostname=hostname))
                    if isinstance(target, TargetIPv4Address):
                        resolutions.add(
                            HostnameIPv4Resolution(hostname=hostname, addr=target.get_addr(), implied=False))
                    elif isinstance(target, TargetIPv6Address):
                        resolutions.add(
                            HostnameIPv6Resolution(hostname=hostname, addr=target.get_addr(), implied=False))

        result.extend(targets)
        result.extend(resolutions)
        result.extend(services)
        return result


fact_reader_registry.append(DnsReconReader())
