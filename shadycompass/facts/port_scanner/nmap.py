import xml.etree.ElementTree as ET
from typing import Iterable
from urllib.parse import urlparse

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, check_file_signature, TargetIPv4Address, TargetHostname, TargetIPv6Address, \
    HostnameIPv4Resolution, HostnameIPv6Resolution, fact_reader_registry, normalize_os_type, Product, parse_products, \
    ScanPresent, OperatingSystem
from shadycompass.facts.services import create_service_facts, spread_addrs
from shadycompass.rules.port_scanner.nmap import NmapRules


def _is_nmap_xml(file_path: str) -> bool:
    return check_file_signature(file_path, '<nmaprun ')


# TODO: parse AD info

class NmapXmlFactReader(FactReader):

    def read_facts(self, file_path: str) -> list[Fact]:
        if not _is_nmap_xml(file_path):
            return []
        print(f"[*] Reading nmap findings from {file_path}")
        result = []
        tree = ET.parse(file_path)
        for host_el in tree.findall('.//host'):
            result.extend(self._parse_host(host_el))
        return result

    def _parse_host(self, host_el: ET.Element) -> list[Fact]:
        result = []
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
                        result.append(TargetHostname(hostname=hostname))
            elif el.tag == 'ports':
                result.extend(self._parse_ports(ipv4.union(ipv6), hostnames, el))

        for addr in ipv4:
            for hostname in hostnames:
                result.append(HostnameIPv4Resolution(hostname=hostname, addr=addr, implied=True))

        for addr in ipv6:
            for hostname in hostnames:
                result.append(HostnameIPv6Resolution(hostname=hostname, addr=addr, implied=True))

        return result

    def _parse_ports(self, addrs: Iterable[str], hostnames: set[str], ports_el: ET.Element) -> list[Fact]:
        result = []
        for port_el in ports_el:
            if port_el.tag != 'port':
                continue
            protocol = port_el.attrib.get('protocol', None)
            port = int(port_el.attrib.get('portid', 0))
            state = 'open'
            service_name = ''
            os_type = None
            secure = False
            for port_detail_el in port_el:
                if not os_type:
                    if port_detail_el.tag == 'service':
                        os_type = os_type or normalize_os_type(
                            port_detail_el.attrib.get('ostype', None),
                            port_detail_el.attrib.get('extrainfo', None))
                    if port_detail_el.tag == 'script' and port_detail_el.attrib.get('id', None) == 'http-server-header':
                        os_type = os_type or normalize_os_type(port_detail_el.attrib.get('output', None))

            for port_detail_el in port_el:
                if port_detail_el.tag == 'state':
                    state = port_detail_el.attrib.get('state', 'unknown')
                elif port_detail_el.tag == 'service':
                    service_name = port_detail_el.attrib.get('name', None)
                    hostname = port_detail_el.attrib.get('hostname', None)
                    extra_info = port_detail_el.attrib.get('extrainfo', None)
                    if port_detail_el.attrib.get('tunnel', None) in ['ssl', 'tls']:
                        secure = True

                    product = port_detail_el.attrib.get('product', None)
                    product_version = port_detail_el.attrib.get('version', None)
                    product_kwargs = {}
                    if hostname:
                        product_kwargs['hostname'] = hostname
                    if os_type:
                        product_kwargs['os_type'] = os_type
                    product_kwargs['port'] = port
                    if product:
                        my_kwargs = product_kwargs.copy()
                        if product_version:
                            my_kwargs['version'] = product_version
                        result.extend(spread_addrs(Product, addrs, product=product, **my_kwargs))
                    if extra_info:
                        for parsed in parse_products(extra_info):
                            my_kwargs = product_kwargs.copy()
                            if parsed.get_version():
                                my_kwargs['version'] = parsed.get_version()
                            result.extend(spread_addrs(Product, addrs, product=parsed.get_product(), **my_kwargs))

            # Look for additional host names, such as http virtual hosts
            for redirect_el in port_el.findall(".//elem[@key='redirect_url']"):
                url = urlparse(redirect_el.text)
                if url.hostname and url.hostname not in hostnames:
                    result.append(TargetHostname(hostname=url.hostname))
                    for addr in addrs:
                        if '.' in addr:
                            result.append(HostnameIPv4Resolution(hostname=url.hostname, addr=addr, implied=True))
                        else:
                            result.append(HostnameIPv6Resolution(hostname=url.hostname, addr=addr, implied=True))

            if state == 'open':
                if os_type:
                    result.extend(spread_addrs(OperatingSystem, addrs, port=port, os_type=os_type))
                create_service_facts(addrs, os_type, port, protocol, result, secure, service_name)

        return result


fact_reader_registry.append(NmapXmlFactReader())
