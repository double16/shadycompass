import json

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, check_file_signature, fact_reader_registry, ScanPresent, Product, \
    OSTYPE_WINDOWS, OSTYPE_LINUX, guess_target, TargetHostname, OSTYPE_MAC, OperatingSystem, WindowsDomain


class Enum4LinuxNGReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, '"smb_domain_info"'):
            return []
        print(f"[*] Reading enum4linux-ng findings from {file_path}")
        result = []
        with open(file_path, 'rt') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return result

        target_host = data.get('target', {}).get('host', '')
        if not target_host:
            return result
        target = guess_target(target_host)
        result.append(target)
        if isinstance(target, TargetHostname):
            target_kwargs = {'hostname': target_host}
        else:
            target_kwargs = {'addr': target_host}

        result.append(ScanPresent(category=ToolCategory.smb_scanner, name='enum4linux-ng', **target_kwargs))

        os_info = data.get('os_info', {})
        os_type = ''
        if os_info.get('OS', ''):
            os_name = os_info.get('OS', '').lower()
            if OSTYPE_WINDOWS in os_name:
                os_type = OSTYPE_WINDOWS
            elif OSTYPE_LINUX in os_name:
                os_type = OSTYPE_LINUX
            elif OSTYPE_MAC in os_name:
                os_type = OSTYPE_MAC
            os_version_parts = [
                os_info.get('OS version'),
                os_info.get('OS build'),
            ]
            os_version = '.'.join(filter(bool, os_version_parts))
            result.append(OperatingSystem(os_type=os_type, name=os_name, version=os_version, **target_kwargs))

        for k, v in data.get('smb_dialects', {}).get('Supported dialects', {}).items():
            if bool(v) and ' ' in k:
                product, version = k.split(maxsplit=1)
                result.append(Product(product=product, version=version, os_type=os_type, **target_kwargs))

        smb_domain_info = data.get('smb_domain_info', {})
        if len(smb_domain_info) > 0:
            windows_domain_dict = {}
            netbios_domain_name = smb_domain_info.get('NetBIOS domain name')
            if netbios_domain_name:
                windows_domain_dict['netbios_domain_name'] = netbios_domain_name
            dns_domain = smb_domain_info.get('DNS domain')
            if dns_domain:
                windows_domain_dict['dns_domain_name'] = dns_domain
            if len(windows_domain_dict) > 0:
                windows_domain = WindowsDomain(**windows_domain_dict)
                result.append(windows_domain)

        return result


fact_reader_registry.append(Enum4LinuxNGReader())
