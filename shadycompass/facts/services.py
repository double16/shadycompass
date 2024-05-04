from typing import Iterable

from experta import Fact

from shadycompass.facts import HttpService, DomainTcpIpService, DomainUdpIpService, TcpIpService, \
    UdpIpService, WinRMService, FtpService, TelnetService, SmtpService, WhoisService, \
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
    MemcacheService, MemcacheDbService, MongoDbService, EtherNetIPService, BacnetService, MsmqService, \
    OSTYPE_WINDOWS, DotNetMessageFramingService, MicrosoftRpcHttpService, SshService


def create_service_facts(addrs: Iterable[str], os_type, port, protocol, result, secure, service_name):
    if service_name == 'http':
        if os_type == OSTYPE_WINDOWS and port == 5985:
            result.extend(spread_addrs(WinRMService, addrs, port=port, secure=secure))
        elif os_type == OSTYPE_WINDOWS and port == 5986:
            result.extend(spread_addrs(WinRMService, addrs, port=port, secure=True))
        else:
            result.extend(spread_addrs(HttpService, addrs, port=port, secure=secure))
    elif service_name == 'https':
        result.extend(spread_addrs(HttpService, addrs, port=port, secure=True))
    elif service_name == 'domain':
        if protocol == 'tcp':
            result.extend(spread_addrs(DomainTcpIpService, addrs, port=port))
        elif protocol == 'udp':
            result.extend(spread_addrs(DomainUdpIpService, addrs, port=port))
    elif service_name == 'ftp':
        result.extend(spread_addrs(FtpService, addrs, port=port, secure=secure))
    elif service_name == 'ftps':
        result.extend(spread_addrs(FtpService, addrs, port=port, secure=True))
    elif service_name in ['ssh', 'openssh']:
        result.extend(spread_addrs(SshService, addrs, port=port))
    elif service_name == 'telnet':
        result.extend(spread_addrs(TelnetService, addrs, port=port, secure=secure))
    elif service_name == 'telnets':
        result.extend(spread_addrs(TelnetService, addrs, port=port, secure=True))
    elif service_name == 'smtp':
        result.extend(spread_addrs(SmtpService, addrs, port=port, secure=secure))
    elif service_name == 'smtps':
        result.extend(spread_addrs(SmtpService, addrs, port=port, secure=True))
    elif service_name == 'whois':
        result.extend(spread_addrs(WhoisService, addrs, port=port))
    elif service_name.startswith('tftp'):
        if protocol == 'tcp':
            result.extend(
                spread_addrs(TftpTcpService, addrs, port=port, secure=secure or service_name.endswith('s')))
        elif protocol == 'udp':
            result.extend(
                spread_addrs(TftpUdpService, addrs, port=port, secure=secure or service_name.endswith('s')))
    elif service_name in ['kerberos-sec', 'kpasswd5']:
        if protocol == 'tcp':
            result.extend(spread_addrs(Kerberos5SecTcpService, addrs, port=port))
        elif protocol == 'udp':
            result.extend(spread_addrs(Kerberos5SecUdpService, addrs, port=port))
    elif service_name == 'kerberos-adm':
        if protocol == 'tcp':
            result.extend(spread_addrs(Kerberos5AdminTcpService, addrs, port=port))
        elif protocol == 'udp':
            result.extend(spread_addrs(Kerberos5AdminUdpService, addrs, port=port))
    elif service_name == 'kerberos':
        if protocol == 'tcp':
            result.extend(spread_addrs(Kerberos4TcpService, addrs, port=port))
        elif protocol == 'udp':
            result.extend(spread_addrs(Kerberos4UdpService, addrs, port=port))
    elif service_name in ['pop2', 'pop3', 'pop3s']:
        result.extend(spread_addrs(PopService, addrs, port=port, secure=secure or service_name.endswith('s')))
    elif service_name == 'rpcbind':
        result.extend(spread_addrs(PortmapperService, addrs, port=port))
    elif service_name == 'ident':
        result.extend(spread_addrs(IdentService, addrs, port=port))
    elif service_name == 'ntp':
        result.extend(spread_addrs(NtpService, addrs, port=port))
    elif service_name == 'msrpc':
        result.extend(spread_addrs(MicrosoftRpcService, addrs, port=port))
    elif service_name == 'ncacn_http':
        result.extend(spread_addrs(MicrosoftRpcHttpService, addrs, port=port))
    elif service_name == 'netbios-ns':
        result.extend(spread_addrs(NetbiosNameService, addrs, port=port))
    elif service_name == 'netbios-dgm':
        result.extend(spread_addrs(NetbiosDatagramService, addrs, port=port))
    elif service_name == 'netbios-ssn':
        result.extend(spread_addrs(NetbiosSessionService, addrs, port=port))
    elif service_name == 'microsoft-ds':
        result.extend(spread_addrs(SmbService, addrs, port=port))
    elif service_name.startswith('imap'):
        result.extend(spread_addrs(
            ImapService, addrs, port=port,
            secure=secure or service_name.endswith('s') or service_name.endswith('ssl')))
    elif service_name == 'snmp':
        result.extend(spread_addrs(SnmpService, addrs, port=port))
    elif service_name.startswith('irc'):
        result.extend(spread_addrs(IrcService, addrs, port=port, secure=secure or service_name.endswith('s')))
    elif service_name.startswith('ldap'):
        result.extend(spread_addrs(
            LdapService, addrs, port=port,
            secure=secure or service_name.endswith('s') or service_name.endswith('ssl')))
    elif service_name.startswith('ldap-admin'):
        result.extend(spread_addrs(LdapAdminService, addrs, port=port, secure=secure))
    elif service_name == 'isakmp':
        result.extend(spread_addrs(IpsecService, addrs, port=port))
    elif service_name == 'mbap':
        result.extend(spread_addrs(ModbusService, addrs, port=port))
    elif service_name == 'exec':
        result.extend(spread_addrs(RexecService, addrs, port=port))
    elif service_name == 'login':
        result.extend(spread_addrs(RloginService, addrs, port=port))
    elif service_name == 'shell':
        result.extend(spread_addrs(RshService, addrs, port=port))
    elif service_name == 'printer':
        result.extend(spread_addrs(LpdService, addrs, port=port))
    elif service_name == 'afp':
        result.extend(spread_addrs(AppleFileProtocol, addrs, port=port))
    elif service_name == 'rtsp':
        result.extend(spread_addrs(RealTimeStreamingProtocol, addrs, port=port))
    elif service_name == 'ipp':
        result.extend(spread_addrs(InternetPrintingProtocol, addrs, port=port))
    elif service_name == 'epp':
        result.extend(spread_addrs(ExtensibleProvisioningProtocol, addrs, port=port))
    elif service_name == 'rsync':
        result.extend(spread_addrs(RsyncService, addrs, port=port))
    elif service_name == 'socks':
        result.extend(spread_addrs(SocksService, addrs, port=port))
    elif service_name == 'ibm-mqseries':
        result.extend(spread_addrs(IbmMqSeriesService, addrs, port=port))
    elif service_name == 'ms-sql-s':
        result.extend(spread_addrs(MssqlService, addrs, port=port))
    elif service_name == 'pptp':
        result.extend(spread_addrs(PptpService, addrs, port=port))
    elif service_name == 'mqtt':
        result.extend(spread_addrs(MqttService, addrs, port=port, secure=secure))
    elif service_name == 'secure-mqtt':
        result.extend(spread_addrs(MqttService, addrs, port=port, secure=True))
    elif service_name == 'nfs':
        result.extend(spread_addrs(NfsService, addrs, port=port))
    elif service_name == 'docker':
        result.extend(spread_addrs(DockerService, addrs, port=port))
    elif service_name == 'squid-http':
        result.extend(spread_addrs(SquidHttpService, addrs, port=port))
    elif service_name == 'squid-ipc':
        result.extend(spread_addrs(SquidIpcService, addrs, port=port))
    elif service_name == 'squid-snmp':
        result.extend(spread_addrs(SquidSnmpService, addrs, port=port))
    elif service_name == 'squid-htcp':
        result.extend(spread_addrs(SquidHtcpService, addrs, port=port))
    elif service_name == 'iscsi':
        result.extend(spread_addrs(IscsiService, addrs, port=port))
    elif service_name == 'saprouter':
        result.extend(spread_addrs(SaprouterService, addrs, port=port))
    elif service_name == 'mysql':
        result.extend(spread_addrs(MysqlService, addrs, port=port))
    elif service_name in ['rdp', 'ms-wbt-server']:
        result.extend(spread_addrs(RdpService, addrs, port=port))
    elif service_name.startswith('distcc'):
        result.extend(spread_addrs(DistccService, addrs, port=port))
    elif service_name == 'svn':
        result.extend(spread_addrs(SvnService, addrs, port=port))
    elif service_name == 'ws-discovery':
        result.extend(spread_addrs(WSDiscoveryService, addrs, port=port))
    elif service_name == 'epmd':
        result.extend(spread_addrs(ErlangPortMapperService, addrs, port=port))
    elif service_name == 'opcua-tcp':
        result.extend(spread_addrs(OpenPlatformCommunicationsUnifiedAccessTcpService, addrs, port=port))
    elif service_name == 'opcua-udp':
        result.extend(spread_addrs(OpenPlatformCommunicationsUnifiedAccessUdpService, addrs, port=port))
    elif service_name == 'mdns':
        result.extend(spread_addrs(MdnsService, addrs, port=port))
    elif service_name == 'zeroconf':
        result.extend(spread_addrs(ZeroconfService, addrs, port=port))
    elif service_name == 'postgresql':
        result.extend(spread_addrs(PostgresqlService, addrs, port=port))
    elif service_name.startswith('amqp'):
        result.extend(
            spread_addrs(AmqpService, addrs, port=port, secure=secure or service_name.endswith('s')))
    elif service_name.startswith('vnc-http'):
        result.extend(spread_addrs(VncHttpService, addrs, port=port))
    elif service_name.startswith('vnc'):
        result.extend(spread_addrs(VncService, addrs, port=port))
    elif service_name == 'couchdb':
        result.extend(spread_addrs(CouchdbService, addrs, port=port))
    elif service_name == 'winrm':
        result.extend(spread_addrs(WinRMService, addrs, port=port, secure=secure))
    elif service_name.startswith('x11') or service_name.startswith('X11'):
        result.extend(spread_addrs(X11Service, addrs, port=port))
    elif service_name == 'redis':
        result.extend(spread_addrs(RedisService, addrs, port=port))
    elif service_name == 'ajp13':
        result.extend(spread_addrs(ApacheJServService, addrs, port=port))
    elif service_name == 'bitcoin':
        result.extend(spread_addrs(BitcoinService, addrs, port=port))
    elif service_name in ['jetdirect', 'hp-pdl-datastr']:
        result.extend(spread_addrs(PDLDataStreamingService, addrs, port=port))
    elif service_name.startswith('ndmp'):
        result.extend(spread_addrs(NetworkDataManagementProtocol, addrs, port=port,
                                   secure=secure or service_name.endswith('s')))
    elif service_name == 'memcache':
        result.extend(spread_addrs(MemcacheService, addrs, port=port))
    elif service_name == 'memcachedb':
        result.extend(spread_addrs(MemcacheDbService, addrs, port=port))
    elif service_name == 'mongod':
        result.extend(spread_addrs(MongoDbService, addrs, port=port))
    elif service_name == 'EtherNetIP-2':
        result.extend(spread_addrs(EtherNetIPService, addrs, port=port))
    elif service_name == 'bacnet':
        result.extend(spread_addrs(BacnetService, addrs, port=port))
    elif service_name == 'msmq':
        result.extend(spread_addrs(MsmqService, addrs, port=port))
    elif service_name == 'mc-nmf':
        result.extend(spread_addrs(DotNetMessageFramingService, addrs, port=port))
    elif protocol == 'tcp':
        result.extend(spread_addrs(TcpIpService, addrs, port=port))
    elif protocol == 'udp':
        result.extend(spread_addrs(UdpIpService, addrs, port=port))


def spread_addrs(fact_type, addrs: Iterable[str], **kwargs) -> list[Fact]:
    result = []
    for addr in addrs:
        result.append(fact_type(addr=addr, **kwargs))
    return result
