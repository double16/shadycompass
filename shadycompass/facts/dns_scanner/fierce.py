import re

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, guess_target, ScanPresent, \
    TargetHostname, remove_terminal_escapes

_FIERCE_LINE_PATTERN = re.compile(r'^(\w+):\s+(\S+)[.]\s+\((\S+)\)$', re.MULTILINE)


class FierceReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, _FIERCE_LINE_PATTERN):
            return []
        print(f"[*] Reading fierce findings from {file_path}")
        targets = set()
        resolutions = set()
        result = []
        targets = set()
        with open(file_path, 'rt') as file:
            for line in remove_terminal_escapes(file.readlines()):
                m = _FIERCE_LINE_PATTERN.search(line)
                if not m:
                    continue
                finding_type = m.group(1)
                hostname = m.group(2)
                addr = m.group(3)
                if finding_type == 'SOA':
                    result.append(ScanPresent(category=ToolCategory.dns_scanner, name='fierce',
                                              hostname=hostname, addr=addr, port=53))
                if finding_type in ['SOA', 'Found']:
                    target = guess_target(addr)
                    targets.add(target)
                    targets.add(TargetHostname(hostname=hostname))
                    resolutions.add(target.get_resolution(hostname, False))

        result.extend(targets)
        result.extend(resolutions)
        return result


fact_reader_registry.append(FierceReader())
