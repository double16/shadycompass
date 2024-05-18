from abc import ABC

from experta import DefFacts, Rule, MATCH, AS, NOT, OR

from shadycompass.config import ToolCategory, ToolAvailable
from shadycompass.facts import ScanNeeded, TargetDomain, WindowsDomain, UsernamePassword
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_LDAP


class LdapSearchRules(IRules, ABC):
    ldapsearch_tool_name = 'ldapsearch'

    @DefFacts()
    def ldapsearch_available(self):
        yield ToolAvailable(
            category=ToolCategory.ldap_scanner,
            name=self.ldapsearch_tool_name,
            tool_links=[
                'https://docs.ldap.com/ldap-sdk/docs/tool-usages/ldapsearch.html',
            ],
            methodology_links=METHOD_LDAP,
        )

    def _compute_ldapsearch_params(self, domain: TargetDomain = None,
                                   windows_domain: WindowsDomain = None,
                                   cred: UsernamePassword = None) -> tuple[str, str, str, str]:
        dns_domain = None
        if windows_domain is not None:
            dns_domain = windows_domain.get_dns_domain_name() or windows_domain.get_dns_tree_name()
        if domain is not None and dns_domain is None:
            dns_domain = domain.get_domain()
        dc = ','.join(map(lambda e: f"DC={e}", dns_domain.split('.')))

        username = ''
        password = ''
        if cred is not None:
            username = cred.get_username()
            password = cred.get_password()
            if windows_domain is not None and windows_domain.get_netbios_domain_name():
                username = f"{windows_domain.get_netbios_domain_name()}\\{username}"

        return dns_domain, dc, username, password

    def _declare_ldapsearch_base(self, f1: ScanNeeded, domain: TargetDomain = None,
                                 windows_domain: WindowsDomain = None, cred: UsernamePassword = None):
        addr = f1.get_addr()
        addr_file_name_part = f'-{addr}'

        dns_domain, dc, username, password = self._compute_ldapsearch_params(domain, windows_domain, cred)
        if dns_domain is None:
            return
        domain_file_name_part = f"-{dns_domain}"

        command_line_base = self.resolve_command_line(
            self.ldapsearch_tool_name,
            [
                '-H', f"ldap://{f1.get_addr()}", '-x', '-D', username, '-w', password, '-b', dc,
            ],
        )
        command_line_base.extend([
            f'>{self.ldapsearch_tool_name}{domain_file_name_part}-base{addr_file_name_part}.txt',
        ])
        self.recommend_tool(
            category=ToolCategory.ldap_scanner,
            name=self.ldapsearch_tool_name,
            variant=f'{dns_domain}-base',
            command_line=command_line_base,
            addr=f1.get_addr(),
            domain=dns_domain,
        )

    def _declare_ldapsearch_namingcontexts(self, f1: ScanNeeded, domain: TargetDomain = None,
                                           windows_domain: WindowsDomain = None, cred: UsernamePassword = None):
        addr = f1.get_addr()
        addr_file_name_part = f'-{addr}'

        _, _, username, password = self._compute_ldapsearch_params(domain, windows_domain, cred)

        command_line_namingcontexts = self.resolve_command_line(
            self.ldapsearch_tool_name,
            [
                '-H', f'ldap://{f1.get_addr()}', '-x', '-D', username, '-w', password, '-s', 'base', 'namingcontexts',
            ],
        )
        command_line_namingcontexts.extend([
            f'>{self.ldapsearch_tool_name}-namingcontexts{addr_file_name_part}.txt',
        ])
        self.recommend_tool(
            category=ToolCategory.ldap_scanner,
            name=self.ldapsearch_tool_name,
            variant='namingcontexts',
            command_line=command_line_namingcontexts,
            addr=f1.get_addr(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.ldap_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(domain=MATCH.domain_name),
        TOOL_PREF(ToolCategory.ldap_scanner, ldapsearch_tool_name),
        TOOL_CONF(ToolCategory.ldap_scanner, ldapsearch_tool_name),
        NOT(WindowsDomain(dns_domain_name=MATCH.domain_name)),
        salience=100,
    )
    def run_ldapsearch_domain(self, f1: ScanNeeded, domain: TargetDomain):
        self._declare_ldapsearch_base(f1, domain=domain)
        self._declare_ldapsearch_namingcontexts(f1, domain=domain)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.ldap_scanner, addr=MATCH.addr),
        AS.domain << WindowsDomain(dns_domain_name=MATCH.domain_name),
        TOOL_PREF(ToolCategory.ldap_scanner, ldapsearch_tool_name),
        TOOL_CONF(ToolCategory.ldap_scanner, ldapsearch_tool_name),
        salience=100,
        )
    def run_ldapsearch_windows_domain(self, f1: ScanNeeded, domain: WindowsDomain):
        self._declare_ldapsearch_base(f1, windows_domain=domain)
        self._declare_ldapsearch_namingcontexts(f1, windows_domain=domain)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.ldap_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(domain=MATCH.domain_name),
        OR(AS.cred << UsernamePassword(addr=MATCH.addr), AS.cred << UsernamePassword(domain=MATCH.domain_name)),
        TOOL_PREF(ToolCategory.ldap_scanner, ldapsearch_tool_name),
        TOOL_CONF(ToolCategory.ldap_scanner, ldapsearch_tool_name),
        NOT(WindowsDomain(dns_domain_name=MATCH.domain_name)),
        )
    def run_ldapsearch_domain_creds(self, f1: ScanNeeded, domain: TargetDomain, cred: UsernamePassword):
        self._declare_ldapsearch_base(f1, domain=domain, cred=cred)
        self._declare_ldapsearch_namingcontexts(f1, domain=domain, cred=cred)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.ldap_scanner, addr=MATCH.addr),
        AS.domain << WindowsDomain(dns_domain_name=MATCH.domain_name),
        OR(AS.cred << UsernamePassword(addr=MATCH.addr), AS.cred << UsernamePassword(domain=MATCH.domain_name)),
        TOOL_PREF(ToolCategory.ldap_scanner, ldapsearch_tool_name),
        TOOL_CONF(ToolCategory.ldap_scanner, ldapsearch_tool_name),
        )
    def run_ldapsearch_windows_domain_creds(self, f1: ScanNeeded, domain: WindowsDomain, cred: UsernamePassword):
        self._declare_ldapsearch_base(f1, windows_domain=domain, cred=cred)
        self._declare_ldapsearch_namingcontexts(f1, windows_domain=domain, cred=cred)
