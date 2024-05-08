import os
import shlex
import shutil
import tempfile
import unittest

from shadycompass import ShadyCompassOps, TargetIPv4Address, TargetIPv6Address, TargetHostname, HostnameIPv4Resolution
from shadycompass.config import set_local_config_path, set_global_config_path, ConfigFact, SECTION_TOOLS, ToolCategory, \
    ToolRecommended, SECTION_OPTIONS
from shadycompass.facts import SshService, DomainTcpIpService, Kerberos5SecTcpService, MicrosoftRpcService, \
    NetbiosSessionService, DomainUdpIpService, Product, OSTYPE_WINDOWS, HttpUrl, ImapService, TargetDomain
from shadycompass.rules.port_scanner.nmap import NmapRules
from tests.tests import assertFactIn, assertFactNotIn


class OutputCapture:
    def __init__(self):
        self.output = ''

    def write(self, text):
        self.output += text

    def flush(self):
        pass


class InputCapture:
    def __init__(self, input_string):
        self.input_string = input_string
        self.position = 0

    def read(self, size=-1):
        if size == -1:
            # Read the entire input string
            result = self.input_string[self.position:]
            self.position = len(self.input_string)
        else:
            # Read up to 'size' characters
            result = self.input_string[self.position:self.position+size]
            self.position += len(result)
        return result


class ShadyCompassOpsTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

        self.local_dir = tempfile.mkdtemp()
        self.local_config = os.path.join(self.local_dir, 'shadycompass.ini')

        self.global_dir = tempfile.mkdtemp()
        self.global_config = os.path.join(self.global_dir, 'shadycompass.ini')
        set_global_config_path(self.global_config)
        self.artifact_dir = tempfile.mkdtemp()

        self.fd_out = OutputCapture()
        self.fd_err = OutputCapture()
        self.fd_in = InputCapture('')

        self.ops = ShadyCompassOps(args=[self.artifact_dir], fd_in=self.fd_in, fd_out=self.fd_out, fd_err=self.fd_err)
        set_local_config_path(self.local_config)

    def tearDown(self):
        shutil.rmtree(self.artifact_dir)
        shutil.rmtree(self.local_dir)
        shutil.rmtree(self.global_dir)
        super().tearDown()

    def test_save_config(self):
        self.ops.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.port_scanner, value='nmap', global0=False))
        self.ops.engine.declare(
            ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='wfuzz', global0=True))
        self.ops.save_config()
        # the content is verified in the test for ShadyCompassEngine
        self.assertTrue(os.stat(self.local_config).st_size > 0)
        self.assertTrue(os.stat(self.global_config).st_size > 0)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_use_tool(self):
        self.ops.use_tool(['use','feroxbuster'])
        assertFactIn(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='feroxbuster', global0=False), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_use_tool_global(self):
        self.ops.use_tool(['use','global','feroxbuster'])
        assertFactIn(ConfigFact(section=SECTION_TOOLS, option=ToolCategory.http_buster, value='feroxbuster', global0=True), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_use_tool_fail(self):
        try:
            self.ops.use_tool(['use','feroxbusted'])
            self.fail('feroxbusted was accepted as a tool name')
        except ValueError:
            pass

    def test_use_tool_option_fail(self):
        try:
            self.ops.use_tool(['use','feroxbusted','--nope'])
            self.fail('--nope was accepted as an option')
        except ValueError:
            pass

    def test_show_config(self):
        self.ops.use_tool(['use','feroxbuster'])
        self.ops.use_tool(['use','global','nmap'])
        self.ops.show_config()
        self.assertTrue('[tools]' in self.fd_out.output)
        self.assertTrue('# global' in self.fd_out.output)

    def test_reset_config_values(self):
        self.ops.use_tool(['use','feroxbuster'])
        self.ops.use_tool(['use','global','nmap'])
        self.ops.reset_config_values()
        configs = [fact for fact in filter(lambda f: isinstance(f, ConfigFact), self.ops.engine.facts.values())]
        self.assertEqual(0, len(configs))
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_set_config_value_no_section(self):
        self.ops.set_config_value(['set','ratelimit', '5'])
        assertFactIn(ConfigFact(section='general', option='ratelimit', value='5', global0=False), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_set_config_value(self):
        self.ops.set_config_value(['set','custom.ratelimit', '5'])
        assertFactIn(ConfigFact(section='custom', option='ratelimit', value='5', global0=False), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_set_config_value_2dots(self):
        self.ops.set_config_value(['set','custom.rate.limit', '5'])
        assertFactIn(ConfigFact(section='custom', option='rate.limit', value='5', global0=False), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_set_config_value_global(self):
        self.ops.set_config_value(['set', 'global', 'ratelimit', '5'])
        assertFactIn(ConfigFact(section='general', option='ratelimit', value='5', global0=True), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_unset_config_value_no_section(self):
        fact = ConfigFact(section='general', option='ratelimit', value='5', global0=False)
        self.ops.engine.declare(fact)
        self.ops.unset_config_value(['unset','ratelimit'])
        assertFactNotIn(fact, self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_unset_config_value(self):
        fact = ConfigFact(section='custom', option='ratelimit', value='5', global0=False)
        self.ops.engine.declare(fact)
        self.ops.unset_config_value(['unset','custom.ratelimit'])
        assertFactNotIn(ConfigFact(section='custom', option='ratelimit', value='5', global0=False), self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_unset_config_value_2dots(self):
        fact = ConfigFact(section='custom', option='rate.limit', value='5', global0=False)
        self.ops.engine.declare(fact)
        self.ops.unset_config_value(['unset','custom.rate.limit'])
        assertFactNotIn(fact, self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_unset_config_value_global(self):
        fact = ConfigFact(section='general', option='ratelimit', value='5', global0=True)
        self.ops.engine.declare(fact)
        self.ops.unset_config_value(['unset', 'global', 'ratelimit'])
        assertFactNotIn(fact, self.ops.engine)
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_tool_info1(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.tool_info(['info', '1'])
        self.assertTrue('dirb' in self.fd_out.output)

    def test_tool_info2(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='feroxbuster'))
        self.ops.tool_info(['info', '2'])
        self.assertTrue('feroxbuster' in self.fd_out.output)

    def test_tool_info3(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='feroxbuster'))
        self.ops.tool_info(['info', '1', '2'])
        self.assertTrue('dirb' in self.fd_out.output)
        self.assertTrue('feroxbuster' in self.fd_out.output)

    def test_tool_info4(self):
        self.ops.engine.declare(ToolRecommended(addr='10.1.1.1', category=ToolCategory.etc_hosts,
                                                name='add `10.1.1.1 shadycompass.test` to /etc/hosts'))
        self.ops.tool_info(['info', '1'])
        self.assertTrue('/etc/hosts' in self.fd_out.output)

    def test_tool_info_NAN(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='feroxbuster'))
        self.ops.tool_info(['info', 'a'])
        self.assertTrue('[-]' in self.fd_out.output)

    def test_tool_info_index_out_of_bounds(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='feroxbuster'))
        self.ops.tool_info(['info', '10'])
        self.assertTrue('[-]' in self.fd_out.output)

    def test_tool_info_name(self):
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='dirb'))
        self.ops.engine.declare(ToolRecommended(category=ToolCategory.http_buster, name='feroxbuster'))
        self.ops.tool_info(['info', 'feroxbuster'])
        self.assertTrue('feroxbuster' in self.fd_out.output)

    def test_tool_info_name_nmap(self):
        self.ops.tool_info(['info', 'nmap'])
        self.assertEqual(3, self.fd_out.output.count('# nmap'))

    def test_gtnw(self):
        self.ops.global_thermo_nuclear_war()
        self.assertTrue(len(self.fd_out.output) > 0)

    def test_show_tools(self):
        self.ops.show_tools([])
        self.assertTrue('# http_buster' in self.fd_out.output)
        self.assertTrue('# port_scanner' in self.fd_out.output)
        self.assertTrue('- nmap' in self.fd_out.output)

    def test_show_targets(self):
        self.ops.engine.declare(TargetIPv4Address(addr='127.0.0.1'))
        self.ops.engine.declare(TargetIPv4Address(addr='127.0.0.2'))
        self.ops.engine.declare(TargetIPv6Address(addr='::1'))
        self.ops.engine.declare(TargetIPv6Address(addr='::2'))
        self.ops.engine.declare(TargetHostname(hostname='localhost'))
        self.ops.engine.declare(TargetHostname(hostname='localhost.localdomain'))
        self.ops.engine.declare(TargetDomain(domain='localdomain.local'))
        self.ops.engine.declare(HostnameIPv4Resolution(hostname='localhost', addr='127.0.0.1'))
        self.ops.engine.declare(HostnameIPv4Resolution(hostname='localhost', addr='::1'))
        self.ops.engine.declare(HostnameIPv4Resolution(hostname='localhost3', addr='::3'))
        self.ops.show_targets([])
        self.assertTrue('- 127.0.0.1 localhost' in self.fd_out.output)
        self.assertTrue('- ::1 localhost' in self.fd_out.output)
        self.assertTrue('- 127.0.0.2' in self.fd_out.output)
        self.assertTrue('- ::2' in self.fd_out.output)
        self.assertTrue('- localhost.localdomain' in self.fd_out.output)
        self.assertTrue('- *.localdomain.local' in self.fd_out.output)
        self.assertFalse('- ::3 localhost3' in self.fd_out.output)

    def test_show_services(self):
        self.ops.engine.declare(SshService(addr='10.0.1.1', port=22))
        self.ops.engine.declare(DomainTcpIpService(addr='10.0.1.1', port=53))
        self.ops.engine.declare(DomainUdpIpService(addr='10.0.1.1', port=53))
        self.ops.engine.declare(ImapService(addr='10.0.1.1', port=993, secure=True))
        self.ops.engine.declare(Kerberos5SecTcpService(addr='10.0.1.1', port=88))
        self.ops.engine.declare(MicrosoftRpcService(addr='10.0.1.1', port=135))
        self.ops.engine.declare(NetbiosSessionService(addr='10.0.1.1', port=139))
        self.ops.show_services([])
        self.assertTrue('- 53/udp ' in self.fd_out.output)
        self.assertTrue('- 53/tcp ' in self.fd_out.output)
        self.assertTrue('- 22/tcp ' in self.fd_out.output)
        self.assertTrue('- 88/tcp ' in self.fd_out.output)
        self.assertTrue('- 135/tcp ' in self.fd_out.output)
        self.assertTrue('- 139/tcp ' in self.fd_out.output)
        self.assertTrue('- 993/tcp imap/ssl,' in self.fd_out.output)

    def test_show_products(self):
        self.ops.engine.declare(Product(product='apache httpd', version='2.4.56', os_type=OSTYPE_WINDOWS,
                                        addr='10.0.1.1', port=443, hostname="www.example.com"))
        self.ops.engine.declare(Product(product='openssl', version='1.1.1t', os_type=OSTYPE_WINDOWS,
                                        addr='10.0.1.1', port=443, hostname="www.example.com"))
        self.ops.engine.declare(Product(product='php', version='8.0.28', os_type=OSTYPE_WINDOWS,
                                        addr='10.0.1.1', port=443, hostname="www.example.com"))
        self.ops.show_products([])
        self.assertTrue('# 10.0.1.1:443' in self.fd_out.output)
        self.assertTrue('- apache httpd/2.4.56' in self.fd_out.output)
        self.assertTrue('- openssl/1.1.1t' in self.fd_out.output)
        self.assertTrue('- php/8.0.28' in self.fd_out.output)

    def test_show_urls(self):
        self.ops.engine.declare(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/examples'))
        self.ops.engine.declare(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/favicon.ico'))
        self.ops.engine.declare(
            HttpUrl(port=443, vhost='shadycompass.test', url='https://shadycompass.test:443/index.php'))
        self.ops.show_urls([])
        self.assertTrue('- https://shadycompass.test:443/examples' in self.fd_out.output)
        self.assertTrue('- https://shadycompass.test:443/favicon.ico' in self.fd_out.output)
        self.assertTrue('- https://shadycompass.test:443/index.php' in self.fd_out.output)

    def test_tool_option_local(self):
        self.ops.tool_option(['option', 'dirb', '-w', 'raft-large-files.txt'])
        value = self.ops.engine.config_get(SECTION_OPTIONS, 'dirb', False)
        self.assertEqual(shlex.join(['-w', 'raft-large-files.txt']), value)
        self.ops.tool_option(['option', 'dirb', '-r'])
        value = self.ops.engine.config_get(SECTION_OPTIONS, 'dirb', False)
        self.assertEqual(shlex.join(['-w', 'raft-large-files.txt', '-r']), value)
        self.assertIsNone(self.ops.engine.config_get(SECTION_OPTIONS, 'dirb', True))

        self.ops.tool_option(['option', 'dirb', '-w', 'raft-large-small.txt'])
        value = self.ops.engine.config_get(SECTION_OPTIONS, 'dirb', False)
        self.assertEqual(shlex.join(['-w', 'raft-large-small.txt', '-r']), value)

        self.ops.use_tool(['use', 'dirb', '--reset-options'])
        value = self.ops.engine.config_get(SECTION_OPTIONS, 'dirb', False)
        self.assertIsNone(value)

    def test_tool_option_global(self):
        self.ops.tool_option(['option', 'global', 'dirb', '-w', 'raft-large-files.txt'])
        value = self.ops.engine.config_get(SECTION_OPTIONS, 'dirb', True)
        self.assertEqual(shlex.join(['-w', 'raft-large-files.txt']), value)
        self.ops.tool_option(['option', 'global', 'dirb', '-r'])
        value = self.ops.engine.config_get(SECTION_OPTIONS, 'dirb', True)
        self.assertEqual(shlex.join(['-w', 'raft-large-files.txt', '-r']), value)
        self.assertIsNone(self.ops.engine.config_get(SECTION_OPTIONS, 'dirb', False))

        self.ops.tool_option(['option', 'global', 'dirb', '-w', 'raft-large-small.txt'])
        value = self.ops.engine.config_get(SECTION_OPTIONS, 'dirb', True)
        self.assertEqual(shlex.join(['-w', 'raft-large-small.txt', '-r']), value)

        self.ops.use_tool(['use', 'global', 'dirb', '--reset-options'])
        value = self.ops.engine.config_get(SECTION_OPTIONS, 'dirb', True)
        self.assertIsNone(value)

    def test_config_ratelimit(self):
        self.ops.use_tool(['use', 'dirb'])
        self.ops.set_config_value(['set', 'ratelimit', '5'])
        self.ops.refresh()
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['-p-', '-sV', '-sC', '-oN', 'nmap-tcp-all.txt', '-oX', 'nmap-tcp-all.xml', '--max-rate', '5',
                          '$IP'],
        ), self.ops.engine)
        assertFactIn(ToolRecommended(
            category=ToolCategory.port_scanner,
            name=NmapRules.nmap_tool_name,
            command_line=['--top-ports=100', '-sV', '-sC', '-oN', 'nmap-tcp-100.txt', '-oX', 'nmap-tcp-100.xml',
                          '--max-rate', '5', '$IP'],
        ), self.ops.engine)
