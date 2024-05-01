import xml.etree.ElementTree as ET
from typing import Iterable

from experta import Fact

from shadycompass.facts import FactReader, check_file_signature, TargetIPv4Address, TargetHostname, TargetIPv6Address, \
    HostnameIPv4Resolution, HostnameIPv6Resolution, HttpService, DomainTcpIpService, DomainUdpIpService, TcpIpService, \
    UdpIpService, fact_reader_registry, WinRMService, FtpService, TelnetService, SmtpService, WhoisService, \
    TftpTcpService, TftpUdpService, Kerberos5SecTcpService, Kerberos5SecUdpService, Kerberos5AdminTcpService, \
    Kerberos5AdminUdpService, Kerberos4TcpService, Kerberos4UdpService, PopService, PortmapperService, IdentService, \
    NtpService, MicrosoftRpcService, NetbiosNameService, NetbiosDatagramService, NetbiosSessionService, SmbService, \
    ImapService, SnmpService, IrcService, LdapService, LdapAdminService, IpsecService, \
    ModbusService, RexecService, RloginService, RshService, LpdService, AppleFileProtocol, RealTimeStreamingProtocol, \
    InternetPrintingProtocol, ExtensibleProvisioningProtocol, RsyncService, SocksService, \
    IbmMqSeriesService, MssqlService, PptpService, MqttService, NfsService, DockerService, \
    SquidHttpService, SquidIpcService, SquidSnmpService, SquidHtcpService, IscsiService, SaprouterService, MysqlService, \
    RdpService, DistccService, SvnService, WSDiscoveryService, ErlangPortMapperService, \
    OpenPlatformCommunicationsUnifiedAccessTcpService, OpenPlatformCommunicationsUnifiedAccessUdpService, MdnsService, \
    ZeroconfService, PostgresqlService, AmqpService, VncHttpService, VncService, CouchdbService, X11Service, \
    RedisService, ApacheJServService, BitcoinService, PDLDataStreamingService, NetworkDataManagementProtocol, \
    MemcacheService, MemcacheDbService, MongoDbService, EtherNetIPService, BacnetService, MsmqService

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
                    # TODO: extract extra host names
                    if ostype == OSTYPE_WINDOWS and port == 5985:
                        result.extend(self._spread_addrs(WinRMService, addrs, port=port, secure=secure))
                    elif ostype == OSTYPE_WINDOWS and port == 5986:
                        result.extend(self._spread_addrs(WinRMService, addrs, port=port, secure=True))
                    else:
                        result.extend(self._spread_addrs(HttpService, addrs, port=port, secure=secure))
                elif service_name == 'https':
                    # TODO: extract extra host names
                    result.extend(self._spread_addrs(HttpService, addrs, port=port, secure=True))
                elif service_name == 'domain':
                    if protocol == 'tcp':
                        result.extend(self._spread_addrs(DomainTcpIpService, addrs, port=port))
                    elif protocol == 'udp':
                        result.extend(self._spread_addrs(DomainUdpIpService, addrs, port=port))
                elif service_name == 'ftp':
                    result.extend(self._spread_addrs(FtpService, addrs, port=port, secure=secure))
                elif service_name == 'ftps':
                    result.extend(self._spread_addrs(FtpService, addrs, port=port, secure=True))
                elif service_name == 'telnet':
                    result.extend(self._spread_addrs(TelnetService, addrs, port=port, secure=secure))
                elif service_name == 'telnets':
                    result.extend(self._spread_addrs(TelnetService, addrs, port=port, secure=True))
                elif service_name == 'smtp':
                    result.extend(self._spread_addrs(SmtpService, addrs, port=port, secure=secure))
                elif service_name == 'smtps':
                    result.extend(self._spread_addrs(SmtpService, addrs, port=port, secure=True))
                elif service_name == 'whois':
                    result.extend(self._spread_addrs(WhoisService, addrs, port=port))
                elif service_name.startswith('tftp'):
                    if protocol == 'tcp':
                        result.extend(self._spread_addrs(TftpTcpService, addrs, port=port, secure=secure or service_name.endswith('s')))
                    elif protocol == 'udp':
                        result.extend(self._spread_addrs(TftpUdpService, addrs, port=port, secure=secure or service_name.endswith('s')))
                elif service_name == 'kerberos-sec':
                    if protocol == 'tcp':
                        result.extend(self._spread_addrs(Kerberos5SecTcpService, addrs, port=port))
                    elif protocol == 'udp':
                        result.extend(self._spread_addrs(Kerberos5SecUdpService, addrs, port=port))
                elif service_name == 'kerberos-adm':
                    if protocol == 'tcp':
                        result.extend(self._spread_addrs(Kerberos5AdminTcpService, addrs, port=port))
                    elif protocol == 'udp':
                        result.extend(self._spread_addrs(Kerberos5AdminUdpService, addrs, port=port))
                elif service_name == 'kerberos':
                    if protocol == 'tcp':
                        result.extend(self._spread_addrs(Kerberos4TcpService, addrs, port=port))
                    elif protocol == 'udp':
                        result.extend(self._spread_addrs(Kerberos4UdpService, addrs, port=port))
                elif service_name in ['pop2', 'pop3', 'pop3s']:
                    result.extend(self._spread_addrs(PopService, addrs, port=port, secure=secure or service_name.endswith('s')))
                elif service_name == 'rpcbind':
                    result.extend(self._spread_addrs(PortmapperService, addrs, port=port))
                elif service_name == 'ident':
                    result.extend(self._spread_addrs(IdentService, addrs, port=port))
                elif service_name == 'ntp':
                    result.extend(self._spread_addrs(NtpService, addrs, port=port))
                elif service_name == 'msrpc':
                    result.extend(self._spread_addrs(MicrosoftRpcService, addrs, port=port))
                elif service_name == 'netbios-ns':
                    result.extend(self._spread_addrs(NetbiosNameService, addrs, port=port))
                elif service_name == 'netbios-dgm':
                    result.extend(self._spread_addrs(NetbiosDatagramService, addrs, port=port))
                elif service_name == 'netbios-ssn':
                    result.extend(self._spread_addrs(NetbiosSessionService, addrs, port=port))
                elif service_name == 'microsoft-ds':
                    result.extend(self._spread_addrs(SmbService, addrs, port=port))
                elif service_name.startswith('imap'):
                    result.extend(self._spread_addrs(
                        ImapService, addrs, port=port,
                        secure=secure or service_name.endswith('s') or service_name.endswith('ssl')))
                elif service_name == 'snmp':
                    result.extend(self._spread_addrs(SnmpService, addrs, port=port))
                elif service_name.startswith('irc'):
                    result.extend(self._spread_addrs(IrcService, addrs, port=port, secure=secure or service_name.endswith('s')))
                elif service_name.startswith('ldap'):
                    result.extend(self._spread_addrs(
                        LdapService, addrs, port=port,
                        secure=secure or service_name.endswith('s') or service_name.endswith('ssl')))
                elif service_name.startswith('ldap-admin'):
                    result.extend(self._spread_addrs(LdapAdminService, addrs, port=port, secure=secure))
                elif service_name == 'isakmp':
                    result.extend(self._spread_addrs(IpsecService, addrs, port=port))
                elif service_name == 'mbap':
                    result.extend(self._spread_addrs(ModbusService, addrs, port=port))
                elif service_name == 'exec':
                    result.extend(self._spread_addrs(RexecService, addrs, port=port))
                elif service_name == 'login':
                    result.extend(self._spread_addrs(RloginService, addrs, port=port))
                elif service_name == 'shell':
                    result.extend(self._spread_addrs(RshService, addrs, port=port))
                elif service_name == 'printer':
                    result.extend(self._spread_addrs(LpdService, addrs, port=port))
                elif service_name == 'afp':
                    result.extend(self._spread_addrs(AppleFileProtocol, addrs, port=port))
                elif service_name == 'rtsp':
                    result.extend(self._spread_addrs(RealTimeStreamingProtocol, addrs, port=port))
                elif service_name == 'ipp':
                    result.extend(self._spread_addrs(InternetPrintingProtocol, addrs, port=port))
                elif service_name == 'epp':
                    result.extend(self._spread_addrs(ExtensibleProvisioningProtocol, addrs, port=port))
                elif service_name == 'rsync':
                    result.extend(self._spread_addrs(RsyncService, addrs, port=port))
                elif service_name == 'socks':
                    result.extend(self._spread_addrs(SocksService, addrs, port=port))
                elif service_name == 'ibm-mqseries':
                    result.extend(self._spread_addrs(IbmMqSeriesService, addrs, port=port))
                elif service_name == 'ms-sql-s':
                    result.extend(self._spread_addrs(MssqlService, addrs, port=port))
                elif service_name == 'pptp':
                    result.extend(self._spread_addrs(PptpService, addrs, port=port))
                elif service_name == 'mqtt':
                    result.extend(self._spread_addrs(MqttService, addrs, port=port, secure=secure))
                elif service_name == 'secure-mqtt':
                    result.extend(self._spread_addrs(MqttService, addrs, port=port, secure=True))
                elif service_name == 'nfs':
                    result.extend(self._spread_addrs(NfsService, addrs, port=port))
                elif service_name == 'docker':
                    result.extend(self._spread_addrs(DockerService, addrs, port=port))
                elif service_name == 'squid-http':
                    result.extend(self._spread_addrs(SquidHttpService, addrs, port=port))
                elif service_name == 'squid-ipc':
                    result.extend(self._spread_addrs(SquidIpcService, addrs, port=port))
                elif service_name == 'squid-snmp':
                    result.extend(self._spread_addrs(SquidSnmpService, addrs, port=port))
                elif service_name == 'squid-htcp':
                    result.extend(self._spread_addrs(SquidHtcpService, addrs, port=port))
                elif service_name == 'iscsi':
                    result.extend(self._spread_addrs(IscsiService, addrs, port=port))
                elif service_name == 'saprouter':
                    result.extend(self._spread_addrs(SaprouterService, addrs, port=port))
                elif service_name == 'mysql':
                    result.extend(self._spread_addrs(MysqlService, addrs, port=port))
                elif service_name == 'ms-wbt-server':
                    result.extend(self._spread_addrs(RdpService, addrs, port=port))
                elif service_name.startswith('distcc'):
                    result.extend(self._spread_addrs(DistccService, addrs, port=port))
                elif service_name == 'svn':
                    result.extend(self._spread_addrs(SvnService, addrs, port=port))
                elif service_name == 'ws-discovery':
                    result.extend(self._spread_addrs(WSDiscoveryService, addrs, port=port))
                elif service_name == 'epmd':
                    result.extend(self._spread_addrs(ErlangPortMapperService, addrs, port=port))
                elif service_name == 'opcua-tcp':
                    result.extend(self._spread_addrs(OpenPlatformCommunicationsUnifiedAccessTcpService, addrs, port=port))
                elif service_name == 'opcua-udp':
                    result.extend(self._spread_addrs(OpenPlatformCommunicationsUnifiedAccessUdpService, addrs, port=port))
                elif service_name == 'mdns':
                    result.extend(self._spread_addrs(MdnsService, addrs, port=port))
                elif service_name == 'zeroconf':
                    result.extend(self._spread_addrs(ZeroconfService, addrs, port=port))
                elif service_name == 'postgresql':
                    result.extend(self._spread_addrs(PostgresqlService, addrs, port=port))
                elif service_name.startswith('amqp'):
                    result.extend(self._spread_addrs(AmqpService, addrs, port=port, secure=secure or service_name.endswith('s')))
                elif service_name.startswith('vnc-http'):
                    result.extend(self._spread_addrs(VncHttpService, addrs, port=port))
                elif service_name.startswith('vnc'):
                    result.extend(self._spread_addrs(VncService, addrs, port=port))
                elif service_name == 'couchdb':
                    result.extend(self._spread_addrs(CouchdbService, addrs, port=port))
                elif service_name == 'winrm':
                    result.extend(self._spread_addrs(WinRMService, addrs, port=port, secure=secure))
                elif service_name.startswith('x11') or service_name.startswith('X11'):
                    result.extend(self._spread_addrs(X11Service, addrs, port=port))
                elif service_name == 'redis':
                    result.extend(self._spread_addrs(RedisService, addrs, port=port))
                elif service_name == 'ajp13':
                    result.extend(self._spread_addrs(ApacheJServService, addrs, port=port))
                elif service_name == 'bitcoin':
                    result.extend(self._spread_addrs(BitcoinService, addrs, port=port))
                elif service_name in ['jetdirect', 'hp-pdl-datastr']:
                    result.extend(self._spread_addrs(PDLDataStreamingService, addrs, port=port))
                elif service_name.startswith('ndmp'):
                    result.extend(self._spread_addrs(NetworkDataManagementProtocol, addrs, port=port, secure=secure or service_name.endswith('s')))
                elif service_name == 'memcache':
                    result.extend(self._spread_addrs(MemcacheService, addrs, port=port))
                elif service_name == 'memcachedb':
                    result.extend(self._spread_addrs(MemcacheDbService, addrs, port=port))
                elif service_name == 'mongod':
                    result.extend(self._spread_addrs(MongoDbService, addrs, port=port))
                elif service_name == 'EtherNetIP-2':
                    result.extend(self._spread_addrs(EtherNetIPService, addrs, port=port))
                elif service_name == 'bacnet':
                    result.extend(self._spread_addrs(BacnetService, addrs, port=port))
                elif service_name == 'msmq':
                    result.extend(self._spread_addrs(MsmqService, addrs, port=port))
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
