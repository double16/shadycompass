import re

from experta import Fact

from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, HostnameIPv6Resolution, \
    HostnameIPv4Resolution

_HOSTS_PATTERN = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)([\s\w.-]+)\s*$', re.MULTILINE)


def _is_hosts_file(file_path: str) -> bool:
    return check_file_signature(file_path, _HOSTS_PATTERN)


class EtcHosts(FactReader):
    def files(self) -> list[str]:
        return [
            '/etc/hosts',
            r'C:\Windows\System32\drivers\etc\hosts',
        ]

    def read_facts(self, file_path: str) -> list[Fact]:
        results = []
        if not _is_hosts_file(file_path):
            return results
        print(f"[*] Reading hosts from {file_path}")
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                match = _HOSTS_PATTERN.match(line)
                if match:
                    addr = match.group(1)
                    hostnames = filter(lambda e: len(e) > 0, map(lambda e: e.strip(), match.group(2).split(' ')))
                    for hostname in hostnames:
                        if ':' in addr:
                            results.append(HostnameIPv6Resolution(hostname=hostname, addr=addr))
                        else:
                            results.append(HostnameIPv4Resolution(hostname=hostname, addr=addr))
        return results


fact_reader_registry.append(EtcHosts())
