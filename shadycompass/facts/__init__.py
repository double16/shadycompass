import abc
import re
from urllib.parse import urlparse

from experta import Fact, Field

HTTP_PATTERN = re.compile(r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')


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


class TargetIPv6Address(Fact):
    addr = Field(str, mandatory=True)

    def get_addr(self) -> str:
        return self.get('addr')


class HostnameIPv4Resolution(Fact):
    hostname = Field(str, mandatory=True)
    addr = Field(str, mandatory=True)

    def get_hostname(self) -> str:
        return self.get('hostname')

    def get_addr(self) -> str:
        return self.get('addr')


class HostnameIPv6Resolution(Fact):
    hostname = Field(str, mandatory=True)
    addr = Field(str, mandatory=True)

    def get_hostname(self) -> str:
        return self.get('hostname')

    def get_addr(self) -> str:
        return self.get('addr')


class TcpIpService(Fact):
    addr = Field(str, mandatory=True)
    port = Field(int, mandatory=True)

    def get_target(self):
        return self.get('addr')

    def get_port(self):
        return self.get('port')


class UdpIpService(Fact):
    addr = Field(str, mandatory=True)
    port = Field(int, mandatory=True)

    def get_target(self):
        return self.get('addr')

    def get_port(self):
        return self.get('port')


class HasTLS(Fact):
    secure = Field(bool, mandatory=True, default=False)

    def is_secure(self) -> bool:
        return bool(self.get('secure'))


class HttpService(TcpIpService, HasTLS):
    pass


class DomainTcpIpService(TcpIpService):
    pass


class DomainUdpIpService(UdpIpService):
    pass


class WinRMService(TcpIpService, HasTLS):
    pass


class FtpService(TcpIpService, HasTLS):
    pass


class TelnetService(TcpIpService, HasTLS):
    pass


class SmtpService(TcpIpService, HasTLS):
    pass


class WhoisService(TcpIpService):
    pass


class TftpUdpService(UdpIpService, HasTLS):
    pass


class TftpTcpService(TcpIpService, HasTLS):
    pass


class Kerberos5SecTcpService(TcpIpService):
    pass


class Kerberos5SecUdpService(UdpIpService):
    pass


class Kerberos5AdminTcpService(TcpIpService):
    pass


class Kerberos5AdminUdpService(UdpIpService):
    pass


class Kerberos4TcpService(TcpIpService):
    pass


class Kerberos4UdpService(UdpIpService):
    pass


class PopService(TcpIpService, HasTLS):
    version = Field(int, mandatory=False, default=3)


class PortmapperService(TcpIpService):
    pass


class IdentService(TcpIpService):
    pass


class NtpService(UdpIpService):
    pass


class MicrosoftRpcService(TcpIpService):
    pass


class NetbiosNameService(UdpIpService):
    pass


class NetbiosDatagramService(UdpIpService):
    pass


class NetbiosSessionService(TcpIpService):
    pass


class SmbService(TcpIpService):
    pass


class ImapService(TcpIpService):
    pass


class SnmpService(UdpIpService):
    pass


class IrcService(TcpIpService, HasTLS):
    pass


class LdapService (TcpIpService, HasTLS):
    pass


class LdapAdminService(TcpIpService, HasTLS):
    pass


class IpsecService(UdpIpService):
    pass


class ModbusService(TcpIpService):
    pass


class RexecService(TcpIpService):
    pass


class RloginService(TcpIpService):
    pass


class RshService(TcpIpService):
    pass


class LpdService(TcpIpService):
    pass


class AppleFileProtocol(TcpIpService):
    pass


class RealTimeStreamingProtocol(TcpIpService):
    pass


class InternetPrintingProtocol(TcpIpService):
    pass


class ExtensibleProvisioningProtocol(TcpIpService):
    pass


class RsyncService(TcpIpService):
    pass


class SocksService(TcpIpService):
    pass


class IbmMqSeriesService(TcpIpService):
    pass


class MssqlService(TcpIpService):
    pass


class PptpService(TcpIpService):
    pass


class MqttService(TcpIpService, HasTLS):
    pass


class NfsService(TcpIpService):
    pass


class DockerService(TcpIpService):
    pass


class SquidHttpService(TcpIpService):
    pass


class SquidIpcService(TcpIpService):
    pass


class SquidSnmpService(TcpIpService):
    pass


class SquidHtcpService(TcpIpService):
    pass


class IscsiService(TcpIpService):
    pass


class SaprouterService(TcpIpService):
    pass


class MysqlService(TcpIpService):
    pass


class RdpService(TcpIpService):
    pass


class DistccService(TcpIpService):
    pass


class SvnService(TcpIpService):
    pass


class WSDiscoveryService(UdpIpService):
    pass


class ErlangPortMapperService(TcpIpService):
    pass


class OpenPlatformCommunicationsUnifiedAccessTcpService(TcpIpService):
    pass


class OpenPlatformCommunicationsUnifiedAccessUdpService(UdpIpService):
    pass


class MdnsService(UdpIpService):
    pass


class ZeroconfService(UdpIpService):
    pass


class PostgresqlService(TcpIpService):
    pass


class AmqpService(TcpIpService, HasTLS):
    pass


class VncService(TcpIpService):
    pass


class VncHttpService(TcpIpService):
    pass


class CouchdbService(TcpIpService):
    pass


class X11Service(TcpIpService):
    pass


class RedisService(TcpIpService):
    pass


class ApacheJServService(TcpIpService):
    pass


class BitcoinService(TcpIpService):
    pass


class PDLDataStreamingService(TcpIpService):
    pass


class NetworkDataManagementProtocol(TcpIpService, HasTLS):
    pass


class MemcacheService(TcpIpService):
    pass


class MemcacheDbService(TcpIpService):
    pass


class MongoDbService(TcpIpService):
    pass


class EtherNetIPService(TcpIpService):
    pass


class BacnetService(UdpIpService):
    pass


class MsmqService(TcpIpService):
    pass


class HttpUrl(Fact):
    addr = Field(str, mandatory=False)
    port = Field(int, mandatory=True)
    vhost = Field(str, mandatory=True)
    url = Field(str, mandatory=True)


def http_url(url: str, **kwargs) -> HttpUrl:
    parsed = urlparse(url)
    port = parsed.port
    if port is None:
        if url.startswith('http:'):
            port = 80
        elif url.startswith('https:'):
            port = 443
    return HttpUrl(port=port, vhost=parsed.hostname, url=url, **kwargs)


class VulnScanNeeded(Fact):
    ANY = ''
    addr = Field(str, mandatory=False)

    def get_addr(self):
        return self.get('addr')


class VulnScanPresent(Fact):
    """
    Indicates a vuln scan was detected. This is necessary because it may not produce findings.
    """
    name = Field(str, mandatory=True)
    addr = Field(str, mandatory=True)


class PortScanNeeded(Fact):
    ANY = ''
    addr = Field(str, mandatory=False)

    def get_addr(self):
        return self.get('addr')


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
