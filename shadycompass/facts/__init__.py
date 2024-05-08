import abc
import ipaddress
import re
from typing import Union
from urllib.parse import urlparse

from experta import Fact, Field

from shadycompass.rules.library import METHOD_POP, METHOD_IMAP

HTTP_PATTERN = re.compile(r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|(%[0-9a-fA-F][0-9a-fA-F]))+')
PRODUCT_PATTERN = re.compile(r'([A-Za-z0-9.-]+)/([0-9]+[.][A-Za-z0-9.]+)')


class FactReader(abc.ABC):
    def files(self) -> list[str]:
        return []

    @abc.abstractmethod
    def read_facts(self, file_path: str) -> list[Fact]:
        pass


fact_reader_registry: list[FactReader] = list()


def check_file_signature(file_path: str, signature) -> bool:
    try:
        if isinstance(signature, bytes):
            open_flags = 'rb'
        else:
            open_flags = 'rt'

        with open(file_path, open_flags) as f:
            content = f.read(4096)

        if isinstance(signature, re.Pattern):
            return signature.search(content) is not None
        else:
            return str(signature) in content
    except UnicodeDecodeError:
        return False


class TargetDomain(Fact):
    domain = Field(str, mandatory=True)

    def get_domain(self) -> str:
        return self.get('domain')


class TargetIPv4Network(Fact):
    network = Field(str, mandatory=True)


class TargetIPv6Network(Fact):
    network = Field(str, mandatory=True)


class TargetHostname(Fact):
    hostname = Field(str, mandatory=True)

    def get_hostname(self) -> str:
        return self.get('hostname')


class TargetIPv4Address(Fact):
    addr = Field(str, mandatory=True)

    def get_addr(self) -> str:
        return self.get('addr')

    def is_private_ip(self):
        try:
            ip_obj = ipaddress.ip_address(self.get_addr())
            return ip_obj.is_private
        except ValueError:
            return False  # Invalid IP address


class TargetIPv6Address(Fact):
    addr = Field(str, mandatory=True)

    def get_addr(self) -> str:
        return self.get('addr')

    def is_private_ip(self):
        try:
            ip_obj = ipaddress.ip_address(self.get_addr())
            return ip_obj.is_private
        except ValueError:
            return False  # Invalid IP address


class HostnameIPv4Resolution(Fact):
    hostname = Field(str, mandatory=True)
    addr = Field(str, mandatory=True)
    implied = Field(bool, mandatory=False, default=True)

    def get_hostname(self) -> str:
        return self.get('hostname')

    def get_addr(self) -> str:
        return self.get('addr')

    def is_implied(self) -> bool:
        return self.get('implied')


class HostnameIPv6Resolution(Fact):
    hostname = Field(str, mandatory=True)
    addr = Field(str, mandatory=True)
    implied = Field(bool, mandatory=False, default=True)

    def get_hostname(self) -> str:
        return self.get('hostname')

    def get_addr(self) -> str:
        return self.get('addr')

    def is_implied(self) -> bool:
        return self.get('implied')


class HasIpService(Fact):
    addr = Field(str, mandatory=True)
    port = Field(int, mandatory=True)

    def get_addr(self):
        return self.get('addr')

    def get_port(self):
        return self.get('port')


class TcpIpService(HasIpService):
    pass


class UdpIpService(HasIpService):
    pass


class HasTLS(Fact):
    secure = Field(bool, mandatory=True, default=False)

    def is_secure(self) -> bool:
        return bool(self.get('secure'))


class HttpService(TcpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web'
    ]


class DomainTcpIpService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns'
    ]


class DomainUdpIpService(UdpIpService):
    methodology_links = DomainTcpIpService.methodology_links


class SshService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh'
    ]


class WinRMService(TcpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm'
    ]


class FtpService(TcpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp'
    ]


class TelnetService(TcpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet'
    ]


class SmtpService(TcpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp'
    ]


class WhoisService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/43-pentesting-whois'
    ]


class TftpUdpService(UdpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/69-udp-tftp'
    ]


class TftpTcpService(TcpIpService, HasTLS):
    methodology_links = TftpUdpService.methodology_links


class Kerberos5SecTcpService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88'
    ]


class Kerberos5SecUdpService(UdpIpService):
    methodology_links = Kerberos5SecTcpService.methodology_links


class Kerberos5AdminTcpService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88'
    ]


class Kerberos5AdminUdpService(UdpIpService):
    methodology_links = Kerberos5AdminTcpService.methodology_links


class Kerberos4TcpService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-kerberos-88'
    ]


class Kerberos4UdpService(UdpIpService):
    methodology_links = Kerberos4TcpService.methodology_links


class PopService(TcpIpService, HasTLS):
    methodology_links = METHOD_POP
    version = Field(int, mandatory=False, default=3)


class PortmapperService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-rpcbind'
    ]


class IdentService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/113-pentesting-ident'
    ]


class NtpService(UdpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ntp'
    ]


class MicrosoftRpcService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc'
    ]


class MicrosoftRpcHttpService(TcpIpService):
    methodology_links = MicrosoftRpcService.methodology_links


class DotNetMessageFramingService(TcpIpService):
    methodology_links = [
    ]


class NetbiosNameService(UdpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/137-138-139-pentesting-netbios'
    ]


class NetbiosDatagramService(UdpIpService):
    methodology_links = NetbiosNameService.methodology_links


class NetbiosSessionService(TcpIpService):
    methodology_links = NetbiosNameService.methodology_links


class SmbService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb'
    ]


class ImapService(TcpIpService, HasTLS):
    methodology_links = METHOD_IMAP
    version = Field(int, mandatory=False, default=4)


class SnmpService(UdpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp'
    ]


class IrcService(TcpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-irc'
    ]


class LdapService (TcpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap'
    ]


class LdapAdminService(TcpIpService, HasTLS):
    methodology_links = LdapService.methodology_links


class IpsecService(UdpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/ipsec-ike-vpn-pentesting'
    ]


class ModbusService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-modbus'
    ]


class RexecService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/512-pentesting-rexec'
    ]


class RloginService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-rlogin'
    ]


class RshService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-rsh'
    ]


class LpdService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/515-pentesting-line-printer-daemon-lpd'
    ]


class AppleFileProtocol(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/515-pentesting-line-printer-daemon-lpd'
    ]


class RealTimeStreamingProtocol(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/554-8554-pentesting-rtsp'
    ]


class InternetPrintingProtocol(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-631-internet-printing-protocol-ipp'
    ]


class ExtensibleProvisioningProtocol(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/700-pentesting-epp'
    ]


class RsyncService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync'
    ]


class SocksService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/1080-pentesting-socks'
    ]


class IbmMqSeriesService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/1414-pentesting-ibmmq'
    ]


class MssqlService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server'
    ]


class PptpService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/1723-pentesting-pptp'
    ]


class MqttService(TcpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/1883-pentesting-mqtt-mosquitto'
    ]


class NfsService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting'
    ]


class DockerService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker'
    ]


class SquidHttpService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid'
    ]


class SquidIpcService(TcpIpService):
    methodology_links = SquidHttpService.methodology_links


class SquidSnmpService(TcpIpService):
    methodology_links = SquidHttpService.methodology_links


class SquidHtcpService(TcpIpService):
    methodology_links = SquidHttpService.methodology_links


class IscsiService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/3260-pentesting-iscsi'
    ]


class SaprouterService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/3299-pentesting-saprouter'
    ]


class MysqlService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql'
    ]


class RdpService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp'
    ]


class DistccService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/3632-pentesting-distcc'
    ]


class SvnService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/3690-pentesting-subversion-svn-server'
    ]


class WSDiscoveryService(UdpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/3702-udp-pentesting-ws-discovery'
    ]


class ErlangPortMapperService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd'
    ]


class OpenPlatformCommunicationsUnifiedAccessTcpService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/4840-pentesting-opc-ua'
    ]


class OpenPlatformCommunicationsUnifiedAccessUdpService(UdpIpService):
    methodology_links = OpenPlatformCommunicationsUnifiedAccessTcpService.methodology_links


class MdnsService(UdpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/5353-udp-multicast-dns-mdns'
    ]


class ZeroconfService(UdpIpService):
    methodology_links = MdnsService.methodology_links


class PostgresqlService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql'
    ]


class AmqpService(TcpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/5671-5672-pentesting-amqp'
    ]


class VncService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/pentesting-vnc'
    ]


class VncHttpService(TcpIpService):
    methodology_links = VncService.methodology_links


class CouchdbService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/5984-pentesting-couchdb'
    ]


class X11Service(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11'
    ]


class RedisService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis'
    ]


class ApacheJServService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/8009-pentesting-apache-jserv-protocol-ajp'
    ]


class BitcoinService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin'
    ]


class PDLDataStreamingService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/9100-pjl'
    ]


class NetworkDataManagementProtocol(TcpIpService, HasTLS):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/10000-network-data-management-protocol-ndmp'
    ]


class MemcacheService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/11211-memcache'
    ]


class MemcacheDbService(TcpIpService):
    methodology_links = MemcacheService.methodology_links


class MongoDbService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/27017-27018-mongodb'
    ]


class EtherNetIPService(TcpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/44818-ethernetip'
    ]


class BacnetService(UdpIpService):
    methodology_links = [
        'https://book.hacktricks.xyz/network-services-pentesting/47808-udp-bacnet'
    ]


class MsmqService(TcpIpService):
    methodology_links = [
        # TODO:
    ]


class HttpUrl(Fact):
    addr = Field(str, mandatory=False)
    port = Field(int, mandatory=True)
    vhost = Field(str, mandatory=True)
    url = Field(str, mandatory=True)

    def get_url(self) -> str:
        return self.get('url')

    def get_vhost(self) -> str:
        return self.get('vhost')


def http_url(url: str, **kwargs) -> HttpUrl:
    parsed = urlparse(url)
    port = parsed.port
    if port is None:
        if url.startswith('http:'):
            port = 80
        elif url.startswith('https:'):
            port = 443
    return HttpUrl(port=port, vhost=parsed.hostname, url=url, **kwargs)


def http_url_targets(facts: list[Fact]) -> list[Fact]:
    """
    Creates TargetHostname, TargetIPv4Address and/or TargetIPv6Address facts from HttpUrl facts. This isn't done with
    rules because the presence of HttpUrl doesn't imply a target. We want the fact reader to make that decision.
    :param facts:
    :return:
    """
    hostnames = set()
    for url_fact in filter(lambda e: isinstance(e, HttpUrl), facts):
        hostnames.add(url_fact.get_vhost())
    return list(map(guess_target, hostnames))


def guess_target(target: str) -> Union[Fact, None]:
    """
    Guesses the type of target, hostname, IPv4 or IPv6.
    :param target:
    :return:
    """
    if not target:
        return None
    # check for network
    if '/' in target:
        try:
            ipaddress.ip_network(target)
            if '.' in target:
                return TargetIPv4Network(network=target)
            else:
                return TargetIPv6Network(network=target)
        except ValueError:
            pass
    # assume host
    try:
        ipaddress.ip_address(target)
        if '.' in target:
            return TargetIPv4Address(addr=target)
        else:
            return TargetIPv6Address(addr=target)
    except ValueError:
        return TargetHostname(hostname=target)


class ScanNeeded(Fact):
    ANY = ''
    category = Field(str, mandatory=True)
    addr = Field(str, mandatory=True)
    port = Field(int, mandatory=False)
    hostname = Field(str, mandatory=False)
    url = Field(str, mandatory=False)

    def get_category(self) -> str:
        return self.get('category')

    def get_addr(self) -> str:
        return self.get('addr')

    def get_port(self) -> Union[int, None]:
        if 'port' not in self:
            return None
        return int(self.get('port'))

    def get_hostname(self) -> Union[str, None]:
        return self.get('hostname')

    def get_url(self) -> Union[str, None]:
        return self.get('url')


class ScanPresent(Fact):
    category = Field(str, mandatory=True)
    name = Field(str, mandatory=True)
    addr = Field(str, mandatory=False)
    port = Field(int, mandatory=False)
    hostname = Field(str, mandatory=False)
    url = Field(str, mandatory=False)


class HttpBustingNeeded(Fact):
    secure = Field(bool, mandatory=True)
    addr = Field(str, mandatory=True)
    port = Field(int, mandatory=True)
    vhost = Field(str, mandatory=True)

    def get_protocol(self) -> str:
        if self.get('secure'):
            return 'https'
        return 'http'

    def get_addr(self) -> str:
        return self.get('addr')

    def get_port(self) -> int:
        return self.get('port')

    def get_vhost(self) -> str:
        return self.get('vhost')

    def get_url(self) -> str:
        return f"{self.get_protocol()}://{self.get_vhost()}:{self.get_port()}"


class OperatingSystem(Fact):
    addr = Field(str, mandatory=False)
    port = Field(int, mandatory=False)
    hostname = Field(str, mandatory=False)
    os_type = Field(str, mandatory=True)  # OSTYPE_* constants: windows, linux, mac, ...
    name = Field(str, mandatory=False)  # Windows, Ubuntu, ...
    version = Field(str, mandatory=False)  # 10 (Windows 10), 22.04 (Ubuntu)
    kernel_version = Field(str, mandatory=False)


OSTYPE_WINDOWS = 'windows'
OSTYPE_LINUX = 'linux'
OSTYPE_MAC = 'mac'


def normalize_os_type(*args) -> Union[str, None]:
    """
    Normalize the operating system name. The input value can be in various forms based on the tool. The result will be
    generic: windows, linux, mac, etc.
    :param value:
    :return: lower case value, attempts to use one of OSTYPE_ constants
    """
    for value in args:
        if value is None:
            continue
        value = str(value).lower()
        if OSTYPE_WINDOWS in value:
            return OSTYPE_WINDOWS
        if OSTYPE_LINUX in value:
            return OSTYPE_LINUX
        if OSTYPE_MAC in value:
            return OSTYPE_MAC
        if 'win64' in value or 'win32' in value:
            return OSTYPE_WINDOWS
    return None


class Product(Fact):
    addr = Field(str, mandatory=False)
    port = Field(int, mandatory=False)
    hostname = Field(str, mandatory=False)
    product = Field(str, mandatory=True)
    """
    Product name without version. Must be lowercase to simplify matching.
    """
    version = Field(str, mandatory=False)
    os_type = Field(str, mandatory=False)

    def __init__(self, *args, **kwargs):
        kwargs_copy = kwargs.copy()
        if 'product' in kwargs_copy:
            kwargs_copy['product'] = kwargs_copy['product'].lower()
        if 'version' in kwargs_copy:
            kwargs_copy['version'] = kwargs_copy['version'].lower()
        if 'os_type' in kwargs_copy:
            kwargs_copy['os_type'] = kwargs_copy['os_type'].lower()
        super().__init__(*args, **kwargs_copy)

    def get_addr(self):
        return self.get('addr')

    def get_port(self):
        if 'port' in self:
            return int(self.get('port'))
        return None

    def get_product(self):
        return self.get('product')

    def get_version(self):
        return self.get('version')

    def get_product_spec(self):
        if 'version' in self:
            return self.get_product() + '/' + self.get_version()
        return self.get_product()


def parse_products(value: str, **kwargs) -> list[Product]:
    if not value:
        return []
    result = set()
    for match in re.findall(PRODUCT_PATTERN, value):
        result.add(Product(product=match[0].lower(), version=match[1].lower(), **kwargs))
    return list(result)


class RateLimitEnable(Fact):
    addr = Field(str, mandatory=True)
    request_per_second = Field(int, mandatory=True)

    def get_addr(self):
        return self.get('addr')

    def get_request_per_second(self) -> int:
        return int(self.get('request_per_second'))


class ProductionTarget(Fact):
    """
    Marks a target as production and needing extra care not to disrupt.
    """
    addr = Field(str, mandatory=True)

    def get_addr(self):
        return self.get('addr')


class PublicTarget(Fact):
    """
    Marks a target as available on the public internet.
    """
    addr = Field(str, mandatory=True)

    def get_addr(self):
        return self.get('addr')


class WindowsDomain(Fact):
    netbios_domain_name = Field(str, mandatory=False)
    dns_domain_name = Field(str, mandatory=False)
    dns_tree_name = Field(str, mandatory=False)

    def get_netbios_domain_name(self) -> str:
        return self.get('netbios_domain_name')

    def get_dns_domain_name(self) -> str:
        return self.get('dns_domain_name')

    def get_dns_tree_name(self) -> str:
        return self.get('dns_tree_name')


class WindowsDomainController(Fact):
    netbios_domain_name = Field(str, mandatory=True)
    netbios_computer_name = Field(str, mandatory=True)
    dns_domain_name = Field(str, mandatory=True)
    dns_tree_name = Field(str, mandatory=True)
    hostname = Field(str, mandatory=True)
    addr = Field(str, mandatory=False)


class TlsCertificate(Fact):
    subjects = Field(list[str], mandatory=True)
    issuer = Field(str, mandatory=False)

    def get_domain(self) -> str:
        fqdn = self.get_fqdn()
        if fqdn.count('.') < 2:
            return fqdn
        return fqdn.split('.', 1)[1]

    def get_fqdn(self) -> str:
        subs: list[str] = list(self.get('subjects'))
        subs.sort(key=lambda e: e.count('.'), reverse=True)
        return subs[0]
