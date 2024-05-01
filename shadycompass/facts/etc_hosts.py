import os.path
import re
from functools import lru_cache

from experta import Fact

from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, HostnameIPv6Resolution, \
    HostnameIPv4Resolution

HOSTS_FILES = [
    '/etc/hosts',
    r'C:\Windows\System32\drivers\etc\hosts',
]

_HOSTS_PATTERN = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)([\s\w.-]+)\s*$', re.MULTILINE)


@lru_cache(maxsize=None)
def get_etc_hosts() -> str:
    for file_path in HOSTS_FILES:
        if os.path.isfile(file_path):
            return file_path
    return HOSTS_FILES[0]


def _is_hosts_file(file_path: str) -> bool:
    return check_file_signature(file_path, _HOSTS_PATTERN)


class EtcHosts(FactReader):
    def files(self) -> list[str]:
        return HOSTS_FILES

    def read_facts(self, file_path: str) -> list[Fact]:
        results = []
        if os.path.basename(file_path) != 'hosts':
            return results
        # if not _is_hosts_file(file_path):
        #     return results
        print(f"[*] Reading hosts from {file_path}")
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                match = _HOSTS_PATTERN.match(line)
                if match:
                    addr = match.group(1)
                    hostnames = filter(lambda e: len(e) > 0, map(lambda e: e.strip(), match.group(2).split(' ')))
                    for hostname in hostnames:
                        if ':' in addr:
                            results.append(HostnameIPv6Resolution(hostname=hostname, addr=addr, implied=False))
                        else:
                            results.append(HostnameIPv4Resolution(hostname=hostname, addr=addr, implied=False))
        return results


fact_reader_registry.append(EtcHosts())
