import shadycompass.rules.dns_scanner.all as dns_scanner
import shadycompass.rules.http_buster.all as http_buster
import shadycompass.rules.port_scanner.all as port_scanner
import shadycompass.rules.smb_scanner.all as smb_scanner
import shadycompass.rules.smtp_scanner.all as smtp_scanner
import shadycompass.rules.vuln_scanner.all as vuln_scanner
from shadycompass.config import ConfigRules
from shadycompass.rules.dnsscanner import DnsScan
from shadycompass.rules.etc_hosts import EtcHostsRules
from shadycompass.rules.httpbusting import HttpBusting
from shadycompass.rules.imapscanner import ImapScan
from shadycompass.rules.misc import ProductionTargetRules, RateLimitRules, PublicAddrRules, MiscRules
from shadycompass.rules.popscanner import PopScan
from shadycompass.rules.portscanner import PortScan
from shadycompass.rules.smbscanner import SmbScan
from shadycompass.rules.smtpscanner import SmtpScan
from shadycompass.rules.vulnscanner import VulnScan


class AllRules(
    http_buster.AllRules,
    port_scanner.AllRules,
    vuln_scanner.AllRules,
    smb_scanner.AllRules,
    smtp_scanner.AllRules,
    dns_scanner.AllRules,
    HttpBusting,
    PortScan,
    VulnScan,
    SmbScan,
    PopScan,
    ImapScan,
    SmtpScan,
    DnsScan,
    ConfigRules,
    EtcHostsRules,
    ProductionTargetRules,
    RateLimitRules,
    PublicAddrRules,
    MiscRules,
):
    """
    Convenience class to collect all rules.
    """
    pass
