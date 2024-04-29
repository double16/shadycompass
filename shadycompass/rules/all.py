from shadycompass.config import ConfigRules
import shadycompass.rules.http_buster.all as http_buster
import shadycompass.rules.port_scanner.all as port_scanner
import shadycompass.rules.vuln_scanner.all as vuln_scanner
from shadycompass.rules.httpbusting import HttpBusting
from shadycompass.rules.portscanner import PortScan
from shadycompass.rules.vulnscanner import VulnScan


class AllRules(
    http_buster.AllRules,
    port_scanner.AllRules,
    vuln_scanner.AllRules,
    HttpBusting,
    PortScan,
    VulnScan,
    ConfigRules,
):
    """
    Convenience class to collect all rules.
    """
    pass
