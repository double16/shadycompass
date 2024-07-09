from abc import ABC
from math import floor

from experta import Rule, DefFacts, AS, MATCH, NOT

from shadycompass.config import ToolCategory, ToolAvailable, PreferredWordlist, OPTION_WORDLIST_FILE, \
    OPTION_WORDLIST_SUBDOMAIN
from shadycompass.facts import HttpBustingNeeded, RateLimitEnable, ScanNeeded
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_HTTP_BRUTE_FORCE, METHOD_HTTP_VIRTUAL_HOSTS


class GoBusterRules(IRules, ABC):
    gobuster_tool_name = 'gobuster'

    @DefFacts()
    def gobuster_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.gobuster_tool_name,
            tool_links=[
                'https://github.com/OJ/gobuster',
                'https://www.kali.org/tools/gobuster/',
            ],
            methodology_links=METHOD_HTTP_BRUTE_FORCE,
        )
        yield ToolAvailable(
            category=ToolCategory.virtualhost_scanner,
            name=self.gobuster_tool_name,
            tool_links=[
                'https://github.com/OJ/gobuster',
                'https://www.kali.org/tools/gobuster/',
            ],
            methodology_links=METHOD_HTTP_VIRTUAL_HOSTS,
        )

    def _gobuster_ratelimit_options(self, ratelimit: RateLimitEnable):
        return ['--threads', '1', '--delay', str(floor(60000 / ratelimit.get_request_per_second())) + "ms"]

    def _declare_gobuster_as_http_buster(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable = None,
                                         wordlist: PreferredWordlist = None):
        more_options = []
        if ratelimit:
            more_options.append(self._gobuster_ratelimit_options(ratelimit))
        if wordlist:
            more_options.append(['-w', wordlist.get_path()])
        command_line = self.resolve_command_line(
            self.gobuster_tool_name,
            [
                'dir', '-k',
                '-o', f"gobuster-{f1.get_port()}-{f1.get_vhost()}.txt",
                '-u', f1.get_url(),
            ], *more_options
        )
        self.recommend_tool(
            category=ToolCategory.http_buster,
            name=self.gobuster_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
            hostname=f1.get_vhost(),
        )

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_FILE),
        TOOL_PREF(ToolCategory.http_buster, gobuster_tool_name),
        TOOL_CONF(ToolCategory.http_buster, gobuster_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_gobuster_as_http_buster(self, f1: HttpBustingNeeded, wordlist: PreferredWordlist):
        self._declare_gobuster_as_http_buster(f1, wordlist=wordlist)

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_FILE),
        TOOL_PREF(ToolCategory.http_buster, gobuster_tool_name),
        TOOL_CONF(ToolCategory.http_buster, gobuster_tool_name),
    )
    def run_gobuster_as_http_buster_ratelimit(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable,
                                              wordlist: PreferredWordlist):
        self._declare_gobuster_as_http_buster(f1, ratelimit, wordlist=wordlist)

    def _declare_gobuster_as_virtualhost_scan(self, f1: ScanNeeded, ratelimit: RateLimitEnable = None,
                                              wordlist: PreferredWordlist = None):
        more_options = []
        if ratelimit:
            more_options.append(self._gobuster_ratelimit_options(ratelimit))
        if wordlist:
            more_options.append(['-w', wordlist.get_path()])
        command_line = self.resolve_command_line(
            self.gobuster_tool_name,
            [
                'vhost', '-k',
                '-o', f"gobuster-vhost-{f1.get_port()}-{f1.get_hostname()}.txt",
                '--append-domain',
                '-u', f1.get_url(),
            ], *more_options
        )
        self.recommend_tool(
            category=ToolCategory.virtualhost_scanner,
            name=self.gobuster_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
            hostname=f1.get_hostname(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.virtualhost_scanner, addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_SUBDOMAIN),
        TOOL_PREF(ToolCategory.http_buster, gobuster_tool_name),
        TOOL_CONF(ToolCategory.http_buster, gobuster_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_gobuster_as_virtualhost_scan(self, f1: ScanNeeded, wordlist: PreferredWordlist):
        self._declare_gobuster_as_virtualhost_scan(f1, wordlist=wordlist)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.virtualhost_scanner, addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_SUBDOMAIN),
        TOOL_PREF(ToolCategory.http_buster, gobuster_tool_name),
        TOOL_CONF(ToolCategory.http_buster, gobuster_tool_name),
    )
    def run_gobuster_as_virtualhost_scan_ratelimit(self, f1: ScanNeeded, ratelimit: RateLimitEnable,
                                                   wordlist: PreferredWordlist):
        self._declare_gobuster_as_virtualhost_scan(f1, ratelimit, wordlist=wordlist)
