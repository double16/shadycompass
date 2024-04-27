import xml.etree.ElementTree as ET
from typing import Iterable

from experta import Fact

from shadycompass.facts import FactReader, check_file_signature, TargetIPv4Address, TargetHostname, TargetIPv6Address, \
    HostnameIPv4Resolution, HostnameIPv6Resolution, HttpService, DomainTcpIpService, DomainUdpIpService, TcpIpService, \
    UdpIpService, fact_reader_registry, WinRMService

OSTYPE_WINDOWS = 'Windows'


def _is_nmap_xml(file_path: str) -> bool:
    return check_file_signature(file_path, '<nmaprun ')


class NmapXmlFactReader(FactReader):

    def read_facts(self, file_path: str) -> list[Fact]:
        if not _is_nmap_xml(file_path):
            return []
        print(f"[*] Reading nmap facts from {file_path}")
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
                elif el.attrib['addrtype'] == 'ipv6':
                    addr = el.attrib['addr']
                    ipv6.add(addr)
                    result.append(TargetIPv6Address(addr=addr))
            elif el.tag == 'hostnames':
                for hostname_el in el:
                    if hostname_el.tag == 'hostname':
                        hostname = hostname_el.attrib['name']
                        hostnames.add(hostname)
                        result.append(TargetHostname(hostname=hostname))
            elif el.tag == 'ports':
                result.extend(self._parse_ports(ipv4.union(ipv6), el))

        for addr in ipv4:
            for hostname in hostnames:
                result.append(HostnameIPv4Resolution(hostname=hostname, addr=addr))

        for addr in ipv6:
            for hostname in hostnames:
                result.append(HostnameIPv6Resolution(hostname=hostname, addr=addr))

        return result

    def _parse_ports(self, addrs: Iterable[str], ports_el: ET.Element) -> list[Fact]:
        result = []
        for port_el in ports_el:
            if port_el.tag != 'port':
                continue
            protocol = port_el.attrib.get('protocol', None)
            port = int(port_el.attrib.get('portid', 0))
            state = 'open'
            service_name = ''
            ostype = None
            secure = False
            for port_detail_el in port_el:
                if port_detail_el.tag == 'state':
                    state = port_detail_el.attrib.get('state', 'unknown')
                elif port_detail_el.tag == 'service':
                    service_name = port_detail_el.attrib.get('name', None)
                    ostype = port_detail_el.attrib.get('ostype', None)
                    if port_detail_el.attrib.get('tunnel', None) in ['ssl', 'tls']:
                        secure = True
            if state == 'open':
                if service_name == 'http':
                    if ostype == OSTYPE_WINDOWS and port == 5985:
                        result.extend(self._spread_addrs(WinRMService, addrs, port=port, secure=secure))
                    elif ostype == OSTYPE_WINDOWS and port == 5986:
                        result.extend(self._spread_addrs(WinRMService, addrs, port=port, secure=True))
                    else:
                        result.extend(self._spread_addrs(HttpService, addrs, port=port, secure=secure))
                elif service_name == 'https':
                    result.extend(self._spread_addrs(HttpService, addrs, port=port, secure=True))
                elif service_name == 'domain':
                    if protocol == 'tcp':
                        result.extend(self._spread_addrs(DomainTcpIpService, addrs, port=port))
                    elif protocol == 'udp':
                        result.extend(self._spread_addrs(DomainUdpIpService, addrs, port=port))
                elif protocol == 'tcp':
                    result.extend(self._spread_addrs(TcpIpService, addrs, port=port))
                elif protocol == 'udp':
                    result.extend(self._spread_addrs(UdpIpService, addrs, port=port))

        return result

    def _spread_addrs(self, fact_type, addrs: Iterable[str], **kwargs) -> list[Fact]:
        result = []
        for addr in addrs:
            result.append(fact_type(addr=addr, **kwargs))
        return result


fact_reader_registry.append(NmapXmlFactReader())
