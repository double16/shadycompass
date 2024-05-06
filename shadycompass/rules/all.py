import shadycompass.rules.http_buster.all as http_buster
import shadycompass.rules.port_scanner.all as port_scanner
import shadycompass.rules.smb_scanner.all as smb_scanner
import shadycompass.rules.vuln_scanner.all as vuln_scanner
from shadycompass.config import ConfigRules
from shadycompass.rules.etc_hosts import EtcHostsRules
from shadycompass.rules.httpbusting import HttpBusting
from shadycompass.rules.misc import ProductionTargetRules, RateLimitRules, PublicAddrRules
from shadycompass.rules.portscanner import PortScan
from shadycompass.rules.smbscanner import SmbScan
from shadycompass.rules.vulnscanner import VulnScan


class AllRules(
    http_buster.AllRules,
    port_scanner.AllRules,
    vuln_scanner.AllRules,
    smb_scanner.AllRules,
    HttpBusting,
    PortScan,
    VulnScan,
    SmbScan,
    ConfigRules,
    EtcHostsRules,
    ProductionTargetRules,
    RateLimitRules,
    PublicAddrRules,
):
    """
    Convenience class to collect all rules.
    """
    pass
