import re
import xml.etree.ElementTree as ET

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, guess_target, TargetHostname, \
    ScanPresent

DNSENUM_FILENAME_PATTERN = re.compile(r'dnsenum(?:-subdomains)?-([^/\\]+[.][a-z]{2,6})(?:-[\w-]+?)?[.]\w{3,5}$')


class DnsEnumReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, '<magictree class="MtBranchObject">'):
            return []
        print(f"[*] Reading dnsenum subdomain findings from {file_path}")
        m = DNSENUM_FILENAME_PATTERN.search(file_path)
        dns_hostname = m.group(1)

        result = []
        targets = set()
        resolutions = set()
        tree = ET.parse(file_path)
        for host_el in tree.findall('.//host'):
            addr = host_el.text.strip()
            hostname_el = host_el.find('hostname')
            if hostname_el is not None:
                hostname = hostname_el.text.strip()
                target = guess_target(addr)
                targets.add(target)
                targets.add(TargetHostname(hostname=hostname))
                resolutions.add(target.get_resolution(hostname, False))

        result.extend(targets)
        result.extend(resolutions)

        if len(result) > 0:
            dns_hostname_args = {}
            if isinstance(guess_target(dns_hostname), TargetHostname):
                dns_hostname_args['hostname'] = dns_hostname
            else:
                dns_hostname_args['addr'] = dns_hostname
            result.append(ScanPresent(category=ToolCategory.dns_scanner, name='dnsenum', port=53, **dns_hostname_args))

        return result


fact_reader_registry.append(DnsEnumReader())
