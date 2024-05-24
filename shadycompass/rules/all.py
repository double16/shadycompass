import shadycompass.rules.dns_scanner.all as dns_scanner
import shadycompass.rules.http_buster.all as http_buster
import shadycompass.rules.kerberos.all as kerberoaster
import shadycompass.rules.ldap_scanner.all as ldap_scanner
import shadycompass.rules.port_scanner.all as port_scanner
import shadycompass.rules.smb_scanner.all as smb_scanner
import shadycompass.rules.smtp_scanner.all as smtp_scanner
import shadycompass.rules.vuln_scanner.all as vuln_scanner
from shadycompass.config import ConfigRules
from shadycompass.rules.asrep_roaster import AsRepRoaster
from shadycompass.rules.dns_scanner import DnsScan
from shadycompass.rules.etc_hosts import EtcHostsRules
from shadycompass.rules.http_busting import HttpBusting
from shadycompass.rules.imap_scanner import ImapScan
from shadycompass.rules.ldap_scanner import LdapScan
from shadycompass.rules.misc import ProductionTargetRules, RateLimitRules, PublicAddrRules, MiscRules
from shadycompass.rules.pop_scanner import PopScan
from shadycompass.rules.port_scanner import PortScan
from shadycompass.rules.scanner import ScanRules
from shadycompass.rules.smb_scanner import SmbScan
from shadycompass.rules.smtp_scanner import SmtpScan
from shadycompass.rules.virtualhost_scanner import VirtualHostScan
from shadycompass.rules.vuln_scanner import VulnScan


class AllRules(
    http_buster.AllRules,
    port_scanner.AllRules,
    vuln_scanner.AllRules,
    smb_scanner.AllRules,
    smtp_scanner.AllRules,
    dns_scanner.AllRules,
    kerberoaster.AllRules,
    ldap_scanner.AllRules,
    HttpBusting,
    ScanRules,
    PortScan,
    VulnScan,
    SmbScan,
    PopScan,
    ImapScan,
    SmtpScan,
    DnsScan,
    AsRepRoaster,
    LdapScan,
    VirtualHostScan,
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
