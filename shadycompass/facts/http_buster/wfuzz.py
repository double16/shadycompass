import json
import re

from experta import Fact

from shadycompass.facts import FactReader, check_file_signature, http_url

WFUZZ_TARGET_PATTERN = re.compile(r'Target:\s+(.*)\s*')
WFUZZ_TXT_PATTERN = re.compile(r'\D(\d\d\d)\s.*\s\d+ L\s.*\s\d+ W\s.*\s\d+\sC.*"(.*)"')


class WfuzzReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if check_file_signature(file_path, WFUZZ_TXT_PATTERN):
            return self._read_txt(file_path)
        if check_file_signature(file_path, '"payload"'):
            return self._read_json(file_path)
        return []

    def _read_txt(self, file_path: str):
        print(f"[*] Reading wfuzz facts from {file_path}")
        result = []
        target = None
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                m = WFUZZ_TARGET_PATTERN.search(line)
                if m:
                    target = m.group(1)
                elif target:
                    m = WFUZZ_TXT_PATTERN.search(line)
                    if m:
                        http_status = int(m.group(1))
                        if http_status not in [404, 403]:
                            result.append(http_url(target.replace('FUZZ', m.group(2))))
        return result

    def _read_json(self, file_path: str):
        result = []
        print(f"[*] Reading wfuzz facts from {file_path}")
        with open(file_path, 'rt') as f:
            data = json.load(f)
        if not isinstance(data, list):
            return result
        for record in data:
            url = record.get('url', None)
            if url:
                result.append(http_url(url))
        return result
