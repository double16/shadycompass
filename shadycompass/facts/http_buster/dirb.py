from experta import Fact

from shadycompass.facts import FactReader, check_file_signature, HTTP_PATTERN, http_url


class DirbReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, 'DIRB v'):
            return []
        print(f"[*] Reading dirb findings from {file_path}")
        result = []
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                if not line.startswith('+ '):
                    continue
                m = HTTP_PATTERN.search(line)
                if m:
                    result.append(http_url(m.group(0)))

        return result
