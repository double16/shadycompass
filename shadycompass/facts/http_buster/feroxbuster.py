import re

from experta import Fact

from shadycompass.facts import FactReader, check_file_signature, http_url, http_url_targets, fact_reader_registry, \
    remove_terminal_escapes

FEROXBUSTER_PATTERN = re.compile(r'^\d\d\d\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(\w+://\S+).*?$', re.MULTILINE)


class FeroxbusterReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, FEROXBUSTER_PATTERN):
            return []
        print(f"[*] Reading feroxbuster findings from {file_path}")
        result = []
        with open(file_path, 'rt') as file:
            for line in remove_terminal_escapes(file.readlines()):
                m = FEROXBUSTER_PATTERN.search(line)
                if m:
                    url_fact = http_url(m.group(1))
                    result.append(url_fact)
        result.extend(http_url_targets(result, infer_virtual_hosts=True))
        return result


fact_reader_registry.append(FeroxbusterReader())
