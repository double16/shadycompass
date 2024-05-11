import re

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, guess_target, TargetHostname, \
    ScanPresent

_DNS_LINE_PATTERN = re.compile(r'^(\S+)[.]\s+\d+\s+IN\s+A+\s+(\S+)$', re.MULTILINE)
_SERVER_PATTERN = re.compile(r'SERVER:\s+(\S+)#(\d+)\((\S+)\)\s+\(([A-Z]+)\)')


class DigReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, '<<>> DiG '):
            return []
        print(f"[*] Reading dig findings from {file_path}")
        targets = set()
        resolutions = set()
        result = []
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                m = _SERVER_PATTERN.search(line)
                if m:
                    hostname_args = dict()
                    target = guess_target(m.group(3))
                    targets.add(target)
                    if isinstance(target, TargetHostname):
                        hostname_args['hostname'] = target.get_hostname()
                    result.append(ScanPresent(category=ToolCategory.dns_scanner, name='dig',
                                              addr=m.group(1), port=int(m.group(2)),
                                              **hostname_args))
                    continue
                if line.startswith(';'):
                    continue
                m = _DNS_LINE_PATTERN.search(line)
                if m:
                    target = guess_target(m.group(2))
                    targets.add(target)
                    hostname = m.group(1).rstrip('.')
                    targets.add(TargetHostname(hostname=hostname))
                    resolutions.add(target.get_resolution(hostname, False))

        result.extend(targets)
        result.extend(resolutions)
        return result


fact_reader_registry.append(DigReader())
