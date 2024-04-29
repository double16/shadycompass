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


class HttpService(TcpIpService):
    secure = Field(bool, mandatory=True)

    def is_secure(self) -> bool:
        return bool(self.get('secure'))


class DomainTcpIpService(TcpIpService):
    pass


class DomainUdpIpService(UdpIpService):
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


class WinRMService(TcpIpService):
    secure = Field(bool, mandatory=True, default=False)

    def is_secure(self) -> bool:
        return bool(self.get('secure'))
