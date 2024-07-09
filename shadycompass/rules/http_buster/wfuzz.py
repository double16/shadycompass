from abc import ABC
from math import floor

from experta import Rule, DefFacts, AS, NOT, MATCH

from shadycompass.config import ToolCategory, ToolAvailable, PreferredWordlist, OPTION_WORDLIST_FILE, \
    OPTION_WORDLIST_SUBDOMAIN
from shadycompass.facts import HttpBustingNeeded, RateLimitEnable, ScanNeeded
from shadycompass.rules.conditions import TOOL_PREF, TOOL_CONF
from shadycompass.rules.irules import IRules
from shadycompass.rules.library import METHOD_HTTP_BRUTE_FORCE, METHOD_HTTP_VIRTUAL_HOSTS


class WfuzzRules(IRules, ABC):
    wfuzz_tool_name = 'wfuzz'

    @DefFacts()
    def wfuzz_available(self):
        yield ToolAvailable(
            category=ToolCategory.http_buster,
            name=self.wfuzz_tool_name,
            tool_links=[
                'http://www.edge-security.com/wfuzz.php',
                'https://www.kali.org/tools/wfuzz/',
            ],
            methodology_links=METHOD_HTTP_BRUTE_FORCE,
        )
        yield ToolAvailable(
            category=ToolCategory.virtualhost_scanner,
            name=self.wfuzz_tool_name,
            tool_links=[
                'http://www.edge-security.com/wfuzz.php',
                'https://www.kali.org/tools/wfuzz/',
            ],
            methodology_links=METHOD_HTTP_VIRTUAL_HOSTS,
        )

    def _wfuzz_ratelimit_options(self, ratelimit: RateLimitEnable):
        return ['-t', '1', '-s', str(floor(60 / ratelimit.get_request_per_second()))]

    def _declare_wfuzz_as_http_buster(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable = None,
                                      wordlist: PreferredWordlist = None):
        more_options = []
        if ratelimit:
            more_options.append(self._wfuzz_ratelimit_options(ratelimit))
        command_line = self.resolve_command_line(
            self.wfuzz_tool_name,
            [
                '-w', wordlist.get_path(),
                '--hc', '404',
                '-f', f'wfuzz-{f1.get_port()}-{f1.get_vhost()}.json,json',
            ], *more_options
        )
        command_line.append(f'{f1.get_url()}/FUZZ')
        self.recommend_tool(
            category=ToolCategory.http_buster,
            name=self.wfuzz_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
            hostname=f1.get_vhost(),
        )

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_FILE),
        TOOL_PREF(ToolCategory.http_buster, wfuzz_tool_name),
        TOOL_CONF(ToolCategory.http_buster, wfuzz_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_wfuzz_as_http_buster(self, f1: HttpBustingNeeded, wordlist: PreferredWordlist):
        self._declare_wfuzz_as_http_buster(f1, wordlist=wordlist)

    @Rule(
        AS.f1 << HttpBustingNeeded(addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_FILE),
        TOOL_PREF(ToolCategory.http_buster, wfuzz_tool_name),
        TOOL_CONF(ToolCategory.http_buster, wfuzz_tool_name),
    )
    def run_wfuzz_as_http_buster_ratelimit(self, f1: HttpBustingNeeded, ratelimit: RateLimitEnable,
                                           wordlist: PreferredWordlist):
        self._declare_wfuzz_as_http_buster(f1, ratelimit, wordlist=wordlist)

    def _declare_wfuzz_as_virtualhost_scan(self, f1: ScanNeeded, ratelimit: RateLimitEnable = None,
                                           wordlist: PreferredWordlist = None):
        protocol = 'https' if f1.is_secure() else 'http'
        url = f"{protocol}://FUZZ.{f1.get_hostname()}:{f1.get_port()}/"

        more_options = []
        if ratelimit:
            more_options.append(self._wfuzz_ratelimit_options(ratelimit))
        command_line = self.resolve_command_line(
            self.wfuzz_tool_name,
            [
                '-w', wordlist.get_path(),
                '--hc', '404',
                '-f', f'wfuzz-vhost-{f1.get_port()}-{f1.get_hostname()}.json,json',
            ], *more_options
        )
        command_line.append(url)
        self.recommend_tool(
            category=ToolCategory.virtualhost_scanner,
            name=self.wfuzz_tool_name,
            variant=None,
            command_line=command_line,
            addr=f1.get_addr(),
            port=f1.get_port(),
            hostname=f1.get_hostname(),
        )

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.virtualhost_scanner, addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_SUBDOMAIN),
        TOOL_PREF(ToolCategory.http_buster, wfuzz_tool_name),
        TOOL_CONF(ToolCategory.http_buster, wfuzz_tool_name),
        NOT(RateLimitEnable(addr=MATCH.addr))
    )
    def run_wfuzz_as_virtualhost_scan(self, f1: ScanNeeded, wordlist: PreferredWordlist):
        self._declare_wfuzz_as_virtualhost_scan(f1, wordlist=wordlist)

    @Rule(
        AS.f1 << ScanNeeded(category=ToolCategory.virtualhost_scanner, addr=MATCH.addr),
        AS.ratelimit << RateLimitEnable(addr=MATCH.addr),
        AS.wordlist << PreferredWordlist(category=OPTION_WORDLIST_SUBDOMAIN),
        TOOL_PREF(ToolCategory.http_buster, wfuzz_tool_name),
        TOOL_CONF(ToolCategory.http_buster, wfuzz_tool_name),
    )
    def run_wfuzz_as_virtualhost_scan_ratelimit(self, f1: ScanNeeded, ratelimit: RateLimitEnable,
                                                wordlist: PreferredWordlist):
        self._declare_wfuzz_as_virtualhost_scan(f1, ratelimit, wordlist=wordlist)
