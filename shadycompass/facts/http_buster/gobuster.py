import re
import urllib.parse

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, check_file_signature, http_url, http_url_targets, fact_reader_registry, \
    remove_terminal_escapes, VirtualHostname, ScanPresent

GOBUSTER_DIR_FILENAME_PATTERN = re.compile(r'gobuster-(\d+)-([^/\\]+[.][a-z]{2,6})(?:-[\w-]+?)?[.]\w{3,5}$')
GOBUSTER_DIR_PATTERN = re.compile(r'(/\S+)\s+.*Status:\s+\d+.*Size:\s+\d+', re.IGNORECASE)

GOBUSTER_VHOST_FILENAME_PATTERN = re.compile(r'gobuster-vhost-(\d+)-([^/\\]+[.][a-z]{2,6})(?:-[\w-]+?)?[.]\w{3,5}$')
GOBUSTER_VHOST_PATTERN = re.compile(r'Found:\s+(\S+?)(:\d+)?\s+Status:\s+(\d+)(?:.*?\[-->\s+(\S+)?])?', re.IGNORECASE)


class GobusterReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if check_file_signature(file_path, GOBUSTER_VHOST_PATTERN):
            return self._read_vhost(file_path)
        if check_file_signature(file_path, GOBUSTER_DIR_PATTERN):
            return self._read_dir(file_path)
        return []

    def _read_dir(self, file_path: str) -> list[Fact]:
        m = GOBUSTER_DIR_FILENAME_PATTERN.search(file_path)
        if not m:
            return []
        print(f"[*] Reading `gobuster dir` findings from {file_path}")
        port = int(m.group(1))
        vhost = m.group(2)
        protocol = 'https' if port % 1000 == 443 else 'http'  # guessing *shrug
        target = f"{protocol}://{vhost}:{port}"
        result = []
        with open(file_path, 'rt') as file:
            for line in remove_terminal_escapes(file.readlines()):
                m = GOBUSTER_DIR_PATTERN.search(line)
                if m:
                    result.append(http_url(target+m.group(1)))
        result.extend(http_url_targets(
            result,
            infer_virtual_hosts=True,
            infer_scan_category_tool_name=(ToolCategory.http_buster, 'gobuster')
        ))
        return result

    def _read_vhost(self, file_path: str) -> list[Fact]:
        print(f"[*] Reading `gobuster vhost` findings from {file_path}")
        result = []
        scan_present_args = dict()
        m = GOBUSTER_VHOST_FILENAME_PATTERN.search(file_path)
        if m:
            port = int(m.group(1))
            scan_present_args['hostname'] = m.group(2)
            result.append(
                ScanPresent(category=ToolCategory.virtualhost_scanner, name='gobuster', port=port, **scan_present_args))
        else:
            port = 80
        secure = port % 1000 == 443  # guessing *shrug
        with open(file_path, 'rt') as file:
            for line in remove_terminal_escapes(file.readlines()):
                m = GOBUSTER_VHOST_PATTERN.search(line)
                if m:
                    hostname=m.group(1)
                    if m.group(2):
                        my_port = int(m.group(2)[1:])
                    else:
                        my_port = port
                    status = int(m.group(3))
                    if status == 302:
                        redirect = m.group(4)
                        if redirect and '://' in redirect:
                            redirect_hostname = urllib.parse.urlparse(redirect).hostname
                            if hostname.endswith(redirect_hostname) and len(hostname) > len(redirect_hostname):
                                continue
                        result.append(VirtualHostname(hostname=hostname, port=my_port, secure=secure))
                    elif status < 400:
                        result.append(VirtualHostname(hostname=hostname, port=my_port, secure=secure))
        return result


fact_reader_registry.append(GobusterReader())
