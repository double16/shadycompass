import re

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, TargetHostname, Username, \
    UsernamePassword, TargetDomain, ScanPresent

_KDCS_SIGNATURE = re.compile(r'>\s\sUsing KDC\(s\):')
_KDC_SERVER = re.compile(r'\b(\S+):(\d+)\b')
_VALID_USERNAME = re.compile(r'\s+VALID\s+USERNAME:\s+(\S+)@(\S+)')
_VALID_USERPASS = re.compile(r'\s+VALID\s+LOGIN[^:]*:\s+(\S+)@([^:\s]+?):(.+)')
_MESSAGE_SUFFIX = re.compile(r'\s\s\(.*?\)$')


class KerbruteReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, _KDCS_SIGNATURE):
            return []
        print(f"[*] Reading kerbrute findings from {file_path}")
        result = []
        domains = set()
        servers = set()
        scan_present = None
        with open(file_path, 'rt') as file:
            reading_kdcs = True
            for line in file.readlines():
                if ' > ' in line:
                    # remove timestamp
                    line = line.split('>', 1)[1]
                line = _MESSAGE_SUFFIX.sub('', line)
                if reading_kdcs:
                    server_found = False
                    for server in _KDC_SERVER.findall(line):
                        hostname = server[0]
                        # port = int(server.group[1])
                        result.append(TargetHostname(hostname=hostname))
                        servers.add(hostname)
                        server_found = True
                    if server_found:
                        continue
                m = _VALID_USERNAME.search(line)
                if m:
                    reading_kdcs = False
                    result.append(Username(username=m.group(1), domain=m.group(2)))
                    domains.add(m.group(2))
                    if scan_present is None:
                        for server in servers:
                            scan_present = ScanPresent(category=ToolCategory.asrep_roaster, name='kerbrute',
                                                       hostname=server)
                else:
                    m = _VALID_USERPASS.search(line)
                    if m:
                        reading_kdcs = False
                        result.append(UsernamePassword(username=m.group(1), domain=m.group(2), password=m.group(3)))
                        domains.add(m.group(2))
                        # if scan_present is None:
                        #     for server in servers:
                        #         scan_present = ScanPresent(category=ToolCategory.password_scanner, name='kerbrute', hostname=server)
        for domain in domains:
            result.append(TargetDomain(domain=domain))
        if scan_present is not None:
            result.append(scan_present)
        return result


fact_reader_registry.append(KerbruteReader())
