import re

from experta import Fact

from shadycompass.facts import FactReader, check_file_signature, http_url

GOBUSTER_FILENAME_PATTERN = re.compile('gobuster-(\d+)-([^/\\\]+\.[a-z]{2,6})(?:-.*?)?\.\w\w\w$')
GOBUSTER_DIR_PATTERN = re.compile(r'(\S+)\s+.*Status:\s+\d+.*Size:\s+\d+')


class GobusterReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if check_file_signature(file_path, GOBUSTER_DIR_PATTERN):
            return self._read_dir(file_path)
        return []

    def _read_dir(self, file_path: str) -> list[Fact]:
        print(f"[*] Reading `gobuster dir` findings from {file_path}")
        m = GOBUSTER_FILENAME_PATTERN.search(file_path)
        if not m:
            return []
        port = int(m.group(1))
        vhost = m.group(2)
        protocol = 'https' if port in [443,8443] else 'http'  # guessing *shrug
        target = f"{protocol}://{vhost}:{port}"
        result = []
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                m = GOBUSTER_DIR_PATTERN.search(line)
                if m:
                    result.append(http_url(target+m.group(1)))
        return result
