import re
import xml.etree.ElementTree as ET
from typing import Iterable, Union
from urllib.parse import urlparse

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, check_file_signature, TargetIPv4Address, TargetIPv6Address, \
    HostnameIPv4Resolution, HostnameIPv6Resolution, fact_reader_registry, normalize_os_type, Product, parse_products, \
    ScanPresent, OperatingSystem, guess_target, WindowsDomain, WindowsDomainController, TlsCertificate, Username, \
    resolve_unescaped_encoding, TargetHostname, VirtualHostname
from shadycompass.facts.services import create_service_facts, spread_addrs
from shadycompass.rules.port_scanner.nmap import NmapRules

_EXTRAINFO_DOMAIN_MATCH = re.compile(r'Domain:\s+(\S+?)0[.],')
_X509v3_SUBJECT_ALT_MATCH = re.compile(r'DNS:([^\s,]+)')


def _is_nmap_xml(file_path: str) -> bool:
    return check_file_signature(file_path, '<nmaprun ')


class NmapXmlFactReader(FactReader):

    def read_facts(self, file_path: str) -> list[Fact]:
        if not _is_nmap_xml(file_path):
            return []
        print(f"[*] Reading nmap findings from {file_path}")
        result = []
        try:
            tree = ET.parse(file_path)
        except ET.ParseError:
            print(f"[!] nmap findings corrupt, ignoring {file_path}")
            return result

        for host_el in tree.findall('.//host'):
            result.extend(self._parse_host(host_el))
        return result

    def _parse_host(self, host_el: ET.Element) -> list[Fact]:
        result = []

        windows_domain = self._parse_windows_domain(host_el)
        if windows_domain:
            result.append(windows_domain)

        hostnames = set()
        ipv4 = set()
        ipv6 = set()
        for el in host_el:
            if el.tag == 'address':
                if el.attrib['addrtype'] == 'ipv4':
                    addr = el.attrib['addr']
                    ipv4.add(addr)
                    result.append(TargetIPv4Address(addr=addr))
                    result.append(ScanPresent(category=ToolCategory.port_scanner, name=NmapRules.nmap_tool_name, addr=addr))
                elif el.attrib['addrtype'] == 'ipv6':
                    addr = el.attrib['addr']
                    ipv6.add(addr)
                    result.append(TargetIPv6Address(addr=addr))
                    result.append(ScanPresent(category=ToolCategory.port_scanner, name=NmapRules.nmap_tool_name, addr=addr))
            elif el.tag == 'hostnames':
                for hostname_el in el:
                    if hostname_el.tag == 'hostname':
                        hostname = hostname_el.attrib['name']
                        hostnames.add(hostname)
                        result.append(guess_target(hostname))
            elif el.tag == 'ports':
                result.extend(self._parse_ports(ipv4.union(ipv6), hostnames, windows_domain, el))

        for addr in ipv4:
            for hostname in hostnames:
                if hostname != addr:
                    result.append(HostnameIPv4Resolution(hostname=hostname, addr=addr, implied=True))

        for addr in ipv6:
            for hostname in hostnames:
                if hostname != addr:
                    result.append(HostnameIPv6Resolution(hostname=hostname, addr=addr, implied=True))

        return result

    def _parse_ports(self, addrs: Iterable[str], hostnames: set[str], windows_domain: WindowsDomain,
                     ports_el: ET.Element) -> list[Fact]:
        result = []
        for port_el in ports_el:
            if port_el.tag != 'port':
                continue
            protocol = port_el.attrib.get('protocol', None)
            port = int(port_el.attrib.get('portid', 0))
            products: list[Product] = []
            state = 'open'
            service_name = ''
            os_type = None
            secure = False
            script_output: dict[str, str] = {}
            for port_detail_el in port_el:
                if port_detail_el.tag == 'script' and port_detail_el.attrib.get('id', None) is not None:
                    script_output[port_detail_el.attrib.get('id')] = port_detail_el.attrib.get('output', '')
                if not os_type:
                    if port_detail_el.tag == 'service':
                        os_type = os_type or normalize_os_type(
                            port_detail_el.attrib.get('ostype', None),
                            port_detail_el.attrib.get('extrainfo', None))
                    if port_detail_el.tag == 'script' and port_detail_el.attrib.get('id', None) == 'http-server-header':
                        os_type = os_type or normalize_os_type(port_detail_el.attrib.get('output', None))
                if port_detail_el.tag == 'script' and port_detail_el.attrib.get('id', None) == 'ssl-cert':
                    cert = self._parse_table_to_dict(port_detail_el)
                    if cert.get('subject', {}).get('commonName'):
                        secure = True
                        issuer = resolve_unescaped_encoding(cert.get('issuer', {}).get('commonName', '').strip())
                        subjects = [resolve_unescaped_encoding(cert.get('subject', {}).get('commonName').strip())]
                        for ext in cert.get('extensions', []):
                            if 'Alternative' in ext.get('name', ''):
                                for match in _X509v3_SUBJECT_ALT_MATCH.finditer(resolve_unescaped_encoding(ext.get('value', ''))):
                                    if match.group(1) not in subjects:
                                        subjects.append(match.group(1))
                        subjects = list(filter(lambda e: '.' in e, subjects))
                        if len(subjects) > 0:
                            result.append(TlsCertificate(subjects=subjects, issuer=issuer))

            product_kwargs = {}
            if os_type:
                product_kwargs['os_type'] = os_type
            product_kwargs['port'] = port
            product_kwargs['secure'] = secure

            for port_detail_el in port_el:
                if port_detail_el.tag == 'state':
                    state = port_detail_el.attrib.get('state', 'unknown')
                elif port_detail_el.tag == 'script' and port_detail_el.attrib.get('id', None) == 'http-generator':
                    for parsed in parse_products(port_detail_el.get('output', None), multiple=False):
                        my_kwargs = product_kwargs.copy()
                        if parsed.get_version():
                            my_kwargs['version'] = parsed.get_version()
                        products.extend(
                            spread_addrs(Product, addrs, hostnames, product=parsed.get_product(), **my_kwargs))
                elif port_detail_el.tag == 'service':
                    service_name = port_detail_el.attrib.get('name', None)
                    confidence = int(port_detail_el.attrib.get('conf', '0'))  # 0-10
                    hostname = port_detail_el.attrib.get('hostname', None)
                    extra_info = port_detail_el.attrib.get('extrainfo', None)
                    if port_detail_el.attrib.get('tunnel', None) in ['ssl', 'tls']:
                        secure = True
                    if service_name == 'pando-pub' and confidence < 8:
                        service_name = 'wudo'

                    product = port_detail_el.attrib.get('product', None)
                    product_version = port_detail_el.attrib.get('version', None)
                    if not product_version:
                        product_version_els = port_el.findall(".//elem[@key='Product_Version']")
                        if product_version_els:
                            product_version = product_version_els[0].text
                    if product:
                        my_kwargs = product_kwargs.copy()
                        if hostname:
                            my_kwargs['hostname'] = hostname
                        if product_version:
                            my_kwargs['version'] = product_version
                        products.extend(spread_addrs(Product, addrs, hostnames, product=product, **my_kwargs))
                    if extra_info:
                        for parsed in parse_products(extra_info):
                            my_kwargs = product_kwargs.copy()
                            if hostname:
                                my_kwargs['hostname'] = hostname
                            if parsed.get_version():
                                my_kwargs['version'] = parsed.get_version()
                            products.extend(
                                spread_addrs(Product, addrs, hostnames, product=parsed.get_product(), **my_kwargs))

                    if product and 'Active Directory' in product:
                        ad_kwargs = dict(hostname=hostname, netbios_computer_name=hostname)

                        if windows_domain:
                            dns_domain_name = windows_domain.get_dns_domain_name()
                            if windows_domain.get_dns_tree_name():
                                ad_kwargs['dns_tree_name'] = windows_domain.get_dns_tree_name()
                            if windows_domain.get_netbios_domain_name():
                                ad_kwargs['netbios_domain_name'] = windows_domain.get_netbios_domain_name()
                        else:
                            m = _EXTRAINFO_DOMAIN_MATCH.search(extra_info)
                            if m:
                                dns_domain_name = m.group(1)
                            else:
                                continue
                        ad_kwargs['dns_domain_name'] = dns_domain_name
                        if not hostname.endswith(dns_domain_name):
                            hostname = hostname + '.' + dns_domain_name
                            ad_kwargs['hostname'] = hostname
                        result.extend(spread_addrs(WindowsDomainController, addrs, **ad_kwargs))

            # Look for additional host names, such as http virtual hosts
            for redirect_el in port_el.findall(".//elem[@key='redirect_url']"):
                url = urlparse(redirect_el.text)
                if url.hostname and url.hostname not in hostnames:
                    url_target = guess_target(url.hostname)
                    if isinstance(url_target, TargetHostname):
                        result.append(
                            VirtualHostname(hostname=url.hostname, domain=list(hostnames)[0], port=port, secure=secure))
                    else:
                        result.append(url_target)
                    for addr in addrs:
                        if '.' in addr:
                            if addr != url.hostname:
                                result.append(HostnameIPv4Resolution(hostname=url.hostname, addr=addr, implied=True))
                        else:
                            if addr != url.hostname:
                                result.append(HostnameIPv6Resolution(hostname=url.hostname, addr=addr, implied=True))

            if 'pop3-capabilities' in script_output or 'pop3-ntlm-info' in script_output:
                result.extend(spread_addrs(ScanPresent, addrs, port=port, category=ToolCategory.pop_scanner, name=NmapRules.nmap_tool_name))

            if 'imap-capabilities' in script_output or 'imap-ntlm-info' in script_output:
                result.extend(spread_addrs(ScanPresent, addrs, port=port, category=ToolCategory.imap_scanner,
                                           name=NmapRules.nmap_tool_name))

            if any(filter(lambda e: e.startswith('smtp-'), script_output.keys())):
                result.extend(spread_addrs(ScanPresent, addrs, port=port, category=ToolCategory.smtp_scanner,
                                           name=NmapRules.nmap_tool_name))
            if 'smtp-enum-users' in script_output:
                smtp_enum_users = list(map(lambda e: e.strip(), script_output['smtp-enum-users'].split(',')))
                # first entry is the SMTP command used
                if len(smtp_enum_users) > 1 and len(smtp_enum_users[0]) == 4:
                    for user in smtp_enum_users[1:]:
                        result.extend(spread_addrs(Username, addrs, hostnames, username=user))

            result.extend(products)

            if state == 'open':
                if os_type:
                    result.extend(spread_addrs(OperatingSystem, addrs, port=port, os_type=os_type))
                create_service_facts(addrs, os_type, port, protocol, result, secure, service_name, products)

        return result

    def _parse_table_to_dict(self, root_el: ET.Element):
        result_dict = dict()
        result_list = list()
        for el in root_el:
            if el.tag == 'table':
                if 'key' in el.attrib:
                    result_dict[el.attrib['key']] = self._parse_table_to_dict(el)
                else:
                    result_list.append(self._parse_table_to_dict(el))
            elif el.tag == 'elem' and 'key' in el.attrib:
                if 'key' in el.attrib:
                    result_dict[el.attrib['key']] = el.text
                else:
                    result_list.append(el.text)
        return result_dict or result_list

    def _parse_windows_domain(self, root_el: ET.Element) -> Union[WindowsDomain, None]:
        netbios_domain_el = root_el.find(".//elem[@key='NetBIOS_Domain_Name']")
        if netbios_domain_el is None:
            return None
        ntlm_dict = {'netbios_domain_name': netbios_domain_el.text}
        dns_domain_el = root_el.find(".//elem[@key='DNS_Domain_Name']")
        if dns_domain_el is not None:
            ntlm_dict['dns_domain_name'] = dns_domain_el.text
        dns_tree_el = root_el.find(".//elem[@key='DNS_Tree_Name']")
        if dns_tree_el is not None:
            ntlm_dict['dns_tree_name'] = dns_tree_el.text
        windows_domain = WindowsDomain(**ntlm_dict)
        return windows_domain


fact_reader_registry.append(NmapXmlFactReader())
