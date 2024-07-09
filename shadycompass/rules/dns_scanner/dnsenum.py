from abc import ABC

from experta import DefFacts, Rule, AS, NOT, MATCH

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory, PreferredWordlist, OPTION_WORDLIST_SUBDOMAIN
from shadycompass.facts import ScanNeeded, TargetDomain, RateLimitEnable, PublicTarget
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_DNS


class DnsEnumRules(IRules, ABC):
    dnsenum_tool_name = 'dnsenum'

    @DefFacts()
    def dnsenum_available(self):
        yield ToolAvailable(
            category=ToolCategory.dns_scanner,
            name=self.dnsenum_tool_name,
            tool_links=[
                'https://github.com/SparrowOchon/dnsenum2',
                'https://www.kali.org/tools/dnsenum/',
            ],
            methodology_links=METHOD_DNS,
        )

    def _declare_dnsenum(self, f1: ScanNeeded, domain: TargetDomain, ratelimit: RateLimitEnable = None,
                         public: PublicTarget = None, wordlist: PreferredWordlist = None):
        addr = f1.get_addr()
        addr_file_name_part = f'-{addr}-{f1.get_port()}'

        if public is None:
            enum_options = ['-p', '0', '-s', '0']
        else:
            enum_options = ['--enum']

        more_options = []
        if ratelimit:
            more_options.append(['--threads', '1'])
        if wordlist:
            more_options.append(['-f', wordlist.get_path()])

        command_line = self.resolve_command_line(
            self.dnsenum_tool_name,
            [
                '--dnsserver', f1.get_addr(),
                *enum_options,
                '-o', f'dnsenum{addr_file_name_part}-subdomains-{domain.get_domain()}.xml',
            ], *more_options
        )
        command_line.extend([domain.get_domain()])
        self.recommend_tool(
            category=ToolCategory.dns_scanner,
            name=self.dnsenum_tool_name,
            variant=domain.get_domain(),
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr, port=53),
        AS.domain << TargetDomain(),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_SUBDOMAIN),
        TOOL_PREF(ToolCategory.dns_scanner, dnsenum_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, dnsenum_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr)),
        NOT(PublicTarget(addr=MATCH.addr)),
    )
    def run_dnsenum(self, f1: ScanNeeded, domain: TargetDomain, wordlist: PreferredWordlist):
        self._declare_dnsenum(f1, domain, wordlist=wordlist)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr, port=53),
        AS.domain << TargetDomain(),
        AS.public << PublicTarget(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_SUBDOMAIN),
        TOOL_PREF(ToolCategory.dns_scanner, dnsenum_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, dnsenum_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr)),
    )
    def run_dnsenum_public(self, f1: ScanNeeded, domain: TargetDomain, public: PublicTarget,
                           wordlist: PreferredWordlist):
        self._declare_dnsenum(f1, domain, public=public, wordlist=wordlist)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr, port=53),
        AS.domain << TargetDomain(),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_SUBDOMAIN),
        TOOL_PREF(ToolCategory.dns_scanner, dnsenum_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, dnsenum_tool_name),
        NOT(PublicTarget(addr=MATCH.addr)),
    )
    def run_dnsenum_ratelimit(self, f1: ScanNeeded, domain: TargetDomain, ratelimit: RateLimitEnable,
                              wordlist: PreferredWordlist):
        self._declare_dnsenum(f1, domain, ratelimit=ratelimit, wordlist=wordlist)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.dns_scanner, addr=MATCH.addr, port=53),
        AS.domain << TargetDomain(),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        AS.public << PublicTarget(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_SUBDOMAIN),
        TOOL_PREF(ToolCategory.dns_scanner, dnsenum_tool_name),
        TOOL_CONF(ToolCategory.dns_scanner, dnsenum_tool_name),
    )
    def run_dnsenum_public_ratelimit(self, f1: ScanNeeded, domain: TargetDomain, ratelimit: RateLimitEnable,
                                     public: PublicTarget, wordlist: PreferredWordlist):
        self._declare_dnsenum(f1, domain, ratelimit=ratelimit, public=public, wordlist=wordlist)
