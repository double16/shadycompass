from abc import ABC

from experta import DefFacts, Rule, AS, MATCH, NOT

from shadycompass import ToolAvailable
from shadycompass.config import ToolCategory, PreferredWordlist, OPTION_WORDLIST_USERNAME
from shadycompass.facts import ScanNeeded, RateLimitEnable, TargetDomain
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_SMTP


class SmtpUserEnumRules(IRules, ABC):
    smtp_user_enum_name = 'smtp-user-enum'

    @DefFacts()
    def smtp_user_enum_available(self):
        yield ToolAvailable(
            category=ToolCategory.smtp_scanner,
            name=self.smtp_user_enum_name,
            tool_links=[
                'http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum',
                'https://www.kali.org/tools/smtp-user-enum/',
            ],
            methodology_links=METHOD_SMTP,
        )

    def _declare_smtp_user_enum(self, f1: ScanNeeded, ratelimit: RateLimitEnable = None, domain: TargetDomain = None,
                                wordlist: PreferredWordlist = None):
        addr = f1.get_addr()
        addr_file_name_part = f'-{addr}-{f1.get_port()}'
        if domain:
            addr_file_name_part += f'-{domain.get_domain()}'

        more_options = []
        if ratelimit:
            more_options.append(['-m', '1'])
        if domain:
            more_options.append(['-D', domain.get_domain()])
            more_options.append(['-f', f'user@{domain.get_domain()}'])

        command_line = self.resolve_command_line(
            self.smtp_user_enum_name,
            [
                '-M', 'VRFY',
                '-U', wordlist.get_path(),
            ], *more_options
        )
        command_line.extend(
            ['-t', addr, '-p', str(f1.get_port()), f'>{self.smtp_user_enum_name}{addr_file_name_part}.txt'])
        self.recommend_tool(
            category=ToolCategory.smtp_scanner,
            name=self.smtp_user_enum_name,
            variant=domain.get_domain() if domain is not None else None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.smtp_scanner, addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_USERNAME),
        TOOL_PREF(ToolCategory.smtp_scanner, smtp_user_enum_name),
        TOOL_CONF(ToolCategory.smtp_scanner, smtp_user_enum_name),
        NOT(RateLimitEnable(addr=MATCH.addr)),
        NOT(TargetDomain())
    )
    def run_smtp_user_enum(self, f1: ScanNeeded, wordlist: PreferredWordlist):
        self._declare_smtp_user_enum(f1, wordlist=wordlist)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.smtp_scanner, addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_USERNAME),
        TOOL_PREF(ToolCategory.smtp_scanner, smtp_user_enum_name),
        TOOL_CONF(ToolCategory.smtp_scanner, smtp_user_enum_name),
        NOT(TargetDomain())
    )
    def run_smtp_user_enum_ratelimit(self, f1: ScanNeeded, ratelimit: RateLimitEnable, wordlist: PreferredWordlist):
        self._declare_smtp_user_enum(f1, ratelimit=ratelimit, wordlist=wordlist)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.smtp_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_USERNAME),
        TOOL_PREF(ToolCategory.smtp_scanner, smtp_user_enum_name),
        TOOL_CONF(ToolCategory.smtp_scanner, smtp_user_enum_name),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_smtp_user_enum_domain(self, f1: ScanNeeded, domain: TargetDomain, wordlist: PreferredWordlist):
        self._declare_smtp_user_enum(f1, domain=domain, wordlist=wordlist)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.smtp_scanner, addr=MATCH.addr),
        AS.domain << TargetDomain(),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_USERNAME),
        TOOL_PREF(ToolCategory.smtp_scanner, smtp_user_enum_name),
        TOOL_CONF(ToolCategory.smtp_scanner, smtp_user_enum_name),
    )
    def run_smtp_user_enum_domain_ratelimit(self, f1: ScanNeeded, domain: TargetDomain, ratelimit: RateLimitEnable,
                                            wordlist: PreferredWordlist):
        self._declare_smtp_user_enum(f1, ratelimit=ratelimit, domain=domain, wordlist=wordlist)
