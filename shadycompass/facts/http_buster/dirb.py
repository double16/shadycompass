from experta import Fact

from shadycompass.facts import FactReader, check_file_signature, HTTP_PATTERN, http_url, http_url_targets, \
    fact_reader_registry, remove_terminal_escapes


class DirbReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, 'DIRB v'):
            return []
        print(f"[*] Reading dirb findings from {file_path}")
        result = []
        with open(file_path, 'rt') as file:
            for line in remove_terminal_escapes(file.readlines()):
                if not line.startswith('+ '):
                    continue
                m = HTTP_PATTERN.search(line)
                if m:
                    result.append(http_url(m.group(0)))
        result.extend(http_url_targets(result))
        return result


fact_reader_registry.append(DirbReader())
