import unittest

from shadycompass.facts import OSTYPE_WINDOWS, normalize_os_type, OSTYPE_LINUX, OSTYPE_MAC, parse_products, Product, \
    TargetIPv4Address, guess_target, TargetIPv6Address, TargetIPv4Network, TargetIPv6Network, TargetHostname


class OperatingSystemTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

    def test_normalize_os_type(self):
        self.assertEqual(OSTYPE_WINDOWS, normalize_os_type('windows'))
        self.assertEqual(OSTYPE_WINDOWS, normalize_os_type('Windows'))
        self.assertEqual(OSTYPE_WINDOWS, normalize_os_type('WINDOWS'))
        self.assertEqual(OSTYPE_WINDOWS, normalize_os_type('Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28'))
        self.assertEqual(OSTYPE_LINUX, normalize_os_type('linux'))
        self.assertEqual(OSTYPE_LINUX, normalize_os_type('Linux'))
        self.assertEqual(OSTYPE_LINUX, normalize_os_type('GNU/Linux'))
        self.assertEqual(OSTYPE_LINUX, normalize_os_type('LINUX'))
        self.assertEqual(OSTYPE_MAC, normalize_os_type('mac'))
        self.assertEqual(OSTYPE_MAC, normalize_os_type('macos'))
        self.assertEqual(OSTYPE_MAC, normalize_os_type('Mac'))
        self.assertEqual(OSTYPE_MAC, normalize_os_type('MacOS'))
        self.assertEqual(OSTYPE_MAC, normalize_os_type('MAC'))


class ProductTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.product_str = 'OpenSSL/1.1.1t PHP/8.0.28'

    def test_parse_product(self):
        parsed = parse_products(self.product_str)
        self.assertIn(Product(product='openssl', version='1.1.1t'), parsed)
        self.assertIn(Product(product='php', version='8.0.28'), parsed)

    def test_parse_product_with_addr(self):
        addr = '192.168.1.1'
        parsed = parse_products(self.product_str, addr=addr)
        self.assertIn(Product(product='openssl', version='1.1.1t', addr=addr), parsed)
        self.assertIn(Product(product='php', version='8.0.28', addr=addr), parsed)


class TargetTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

    def test_ipv4_host(self):
        self.assertEqual(TargetIPv4Address(addr='10.1.1.1'), guess_target('10.1.1.1'))
        self.assertEqual(TargetIPv4Address(addr='127.0.0.1'), guess_target('127.0.0.1'))

    def test_ipv6_host(self):
        self.assertEqual(TargetIPv6Address(addr='2607:f8b0:4002:c1b::6a'), guess_target('2607:f8b0:4002:c1b::6a'))
        self.assertEqual(TargetIPv6Address(addr='::1'), guess_target('::1'))

    def test_ipv4_network(self):
        self.assertEqual(TargetIPv4Network(network='192.168.1.0/24'), guess_target('192.168.1.0/24'))

    def test_ipv6_network(self):
        self.assertEqual(TargetIPv6Network(network='2001:0db8:85a3::/64'), guess_target('2001:0db8:85a3::/64'))

    def test_hostname(self):
        self.assertEqual(TargetHostname(hostname='localhost'), guess_target('localhost'))
        self.assertEqual(TargetHostname(hostname='shadycompass.test'), guess_target('shadycompass.test'))
        self.assertEqual(TargetHostname(hostname='www64.example.com'), guess_target('www64.example.com'))
