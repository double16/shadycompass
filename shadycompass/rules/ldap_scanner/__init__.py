from abc import ABC

from experta import Rule, NOT, MATCH, AS

from shadycompass.config import ToolCategory, ToolRecommended
from shadycompass.facts import ScanNeeded, ScanPresent, LdapService, WindowsDomainController
from shadycompass.rules.irules import IRules


class LdapScan(IRules, ABC):
    @Rule(
        LdapService(addr=MATCH.addr),
        NOT(ScanPresent(category=ToolCategory.ldap_scanner, addr=MATCH.addr)),
        NOT(ScanNeeded(category=ToolCategory.ldap_scanner, addr=MATCH.addr)),
        salience=100
    )
    def need_ldap_scan_addr(self, addr: str):
        self.declare(ScanNeeded(category=ToolCategory.ldap_scanner, addr=addr))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.ldap_scanner, addr=MATCH.addr),
        ScanPresent(category=ToolCategory.ldap_scanner, addr=MATCH.addr),
    )
    def do_not_need_ldap_scan_addr(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.ldap_scanner, addr=MATCH.addr),
        ScanPresent(category=ToolCategory.ldap_scanner, addr=MATCH.addr),
    )
    def retract_ldap_scan_tool_addr(self, f1: ToolRecommended):
        self.retract(f1)

    @Rule(
        AS.f1 << WindowsDomainController(addr=MATCH.addr),
        NOT(ScanPresent(category=ToolCategory.ldap_scanner, addr=MATCH.addr)),
        NOT(ScanNeeded(category=ToolCategory.ldap_scanner, addr=MATCH.addr)),
        salience=100
    )
    def windows_domain_controller_needs_ldap_scan_by_addr(self, f1: WindowsDomainController, addr: str):
        self.declare(ScanNeeded(category=ToolCategory.ldap_scanner, addr=addr))

    @Rule(
        AS.f1 << WindowsDomainController(hostname=MATCH.hostname),
        NOT(ScanPresent(category=ToolCategory.ldap_scanner, hostname=MATCH.hostname)),
        NOT(ScanNeeded(category=ToolCategory.ldap_scanner, hostname=MATCH.hostname)),
        salience=100
    )
    def windows_domain_controller_needs_ldap_scan_by_hostname(self, f1: WindowsDomainController, hostname: str):
        self.declare(ScanNeeded(category=ToolCategory.ldap_scanner, hostname=hostname))

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.ldap_scanner, hostname=MATCH.hostname),
        ScanPresent(category=ToolCategory.ldap_scanner, hostname=MATCH.hostname),
    )
    def do_not_need_ldap_scan_hostname(self, f1: ScanNeeded):
        self.retract(f1)

    @Rule(
        AS.f1 << ToolRecommended(category=ToolCategory.ldap_scanner, hostname=MATCH.hostname),
        ScanPresent(category=ToolCategory.ldap_scanner, hostname=MATCH.hostname),
    )
    def retract_ldap_scan_tool_hostname(self, f1: ToolRecommended):
        self.retract(f1)
