import base64
import binascii
from collections import defaultdict
from typing import Union

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, Username, TargetHostname, \
    TargetDomain, extract_from_file_path, ScanPresent, WindowsDomain, normalize_os_type, OperatingSystem


def read_lines_with_single_space_continuation(file_path):
    with open(file_path, 'r') as file:
        continuation_line = ""
        for line in file:
            stripped_line = line.rstrip()
            if stripped_line.startswith(" "):
                continuation_line += stripped_line[1:]
            else:
                yield continuation_line
                continuation_line = stripped_line
        if continuation_line:
            yield continuation_line


class LdapSearchReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, '# extended LDIF'):
            return []
        result = []
        file_path_info = extract_from_file_path(file_path)
        dns_domain_to_windows_domain: dict[str, str] = dict()
        dns_domain_to_mastered_by: dict[str, str] = dict()
        if 'ipv4' in file_path_info:
            ldap_address = file_path_info.get('ipv4')
        elif 'ipv6' in file_path_info:
            ldap_address = file_path_info.get('ipv6')
        else:
            ldap_address = None
        ldap_hostname = None
        windows_domain: Union[str, None] = None
        ldap_object = defaultdict(list)

        for line in read_lines_with_single_space_continuation(file_path):
            if line.startswith('#'):
                continue
            if len(line) == 0:
                # end of object
                if 'dn' in ldap_object:
                    facts = self._parse_object(ldap_object, dns_domain_to_windows_domain, dns_domain_to_mastered_by,
                                               windows_domain)
                    result.extend(facts)
                    ldap_object.clear()
                    if windows_domain is None:
                        for fact in filter(lambda e: isinstance(e, WindowsDomain), facts):
                            windows_domain = fact.get_netbios_domain_name()
                continue
            if ':' not in line:
                continue
            if '::' in line:
                # base64 encoded
                key, value = line.split('::', 1)
                value = value.strip()
                try:
                    value = base64.b64decode(value)
                except binascii.Error:
                    # use value as is
                    pass
            else:
                # raw data
                key, value = line.split(':', 1)
                value = value.strip()
            if 'dn' in ldap_object or key == 'dn':
                ldap_object[key].append(value)

        if 'dn' in ldap_object:
            result.extend(self._parse_object(ldap_object, dns_domain_to_windows_domain, dns_domain_to_mastered_by,
                                             windows_domain))

        if len(result) > 0:
            scan_attributes = {}
            if ldap_address is not None:
                scan_attributes['addr'] = ldap_address
            if ldap_hostname is not None:
                scan_attributes['hostname'] = ldap_hostname
            elif len(dns_domain_to_mastered_by) > 0:
                ldap_dc = self._find_computer_name(list(dns_domain_to_mastered_by.values()), result)
                if ldap_dc is not None:
                    scan_attributes['hostname'] = ldap_dc

            if len(scan_attributes) > 0:
                result.append(ScanPresent(category=ToolCategory.ldap_scanner, name='ldapsearch', **scan_attributes))

        return result

    def _parse_object(self, ldap_object: defaultdict,
                      dns_domain_to_windows_domain: dict[str, str],
                      dns_domain_to_mastered_by: dict[str, str],
                      windows_domain: Union[str, None]) -> list[Fact]:
        objectclass = ldap_object.get('objectClass')
        if not objectclass:
            return []
        domain = self._parse_domain(ldap_object)
        if 'computer' in objectclass:
            if 'cn' in ldap_object:
                hostname = ldap_object.get('cn')[0] + '.' + domain
                result = [TargetHostname(hostname=hostname)]
                if 'operatingSystem' in ldap_object:
                    os_version: list[str] = ldap_object['operatingSystem'].copy()
                    if 'operatingSystemVersion' in ldap_object:
                        os_version.extend(ldap_object['operatingSystemVersion'])
                    os_version_str = ' '.join(os_version)
                    os_type = normalize_os_type(os_version_str)
                    result.append(OperatingSystem(hostname=hostname, os_type=os_type, version=os_version_str))
                return result
        elif 'user' in objectclass:
            if 'cn' in ldap_object:
                return [Username(username=ldap_object.get('cn')[0], domain=windows_domain or domain)]
        elif 'domain' in objectclass or 'domainDNS' in objectclass:
            if 'distinguishedName' in ldap_object:
                result = []
                target_domain = TargetDomain(domain=self._parse_domain(ldap_object, key='distinguishedName'))
                result.append(target_domain)

                if 'name' in ldap_object:
                    windows_domain = ldap_object.get('name')[0]
                elif 'dc' in ldap_object:
                    windows_domain = ldap_object.get('dc')[0]
                else:
                    windows_domain = None
                if windows_domain is not None:
                    dns_domain_to_windows_domain[target_domain.get_domain()] = windows_domain
                    if 'masteredBy' in ldap_object:
                        dns_domain_to_mastered_by[target_domain.get_domain()] = ldap_object.get('masteredBy')[0]
                    result.append(
                        WindowsDomain(netbios_domain_name=windows_domain, dns_domain_name=target_domain.get_domain()))

                return result

        return []

    def _parse_domain(self, ldap_object: dict[str, list[str]], key: str = 'dn') -> str:
        dn = ','.join(ldap_object.get(key))
        return '.'.join(map(lambda e: e[3:], filter(lambda e: e.startswith('DC='), dn.split(','))))

    def _find_computer_name(self, ldap_values: list[str], facts: list[Fact]) -> Union[str, None]:
        hostnames = list(map(lambda e: e.get('hostname'), filter(lambda e: isinstance(e, TargetHostname), facts)))
        for ldap_value in ldap_values:
            domain = self._parse_domain({'dn': [ldap_value]})
            cns = set(map(lambda e: e[3:], filter(lambda e: e.startswith('CN='), ldap_value.split(','))))
            for cn in cns:
                hostname = f"{cn}.{domain}"
                if hostname in hostnames:
                    return hostname
        return None


fact_reader_registry.append(LdapSearchReader())
