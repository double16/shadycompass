import re

from experta import Fact

from shadycompass.facts import FactReader, check_file_signature, http_url

FEROXBUSTER_PATTERN = re.compile(r'\d\d\d\s+\w+\s+\d+l\s+\d+w\s+\d+c\s+(\w+://.+)')


class FeroxbusterReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, FEROXBUSTER_PATTERN):
            return []
        print(f"[*] Reading feroxbuster facts from {file_path}")
        result = []
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                m = FEROXBUSTER_PATTERN.search(line)
                if m:
                    result.append(http_url(m.group(1)))
        return result
