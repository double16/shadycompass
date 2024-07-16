import unittest

from shadycompass.facts import parse_cpe, Product, OperatingSystem, OSTYPE_WINDOWS, OSTYPE_LINUX, OSTYPE_MAC


class ParseCpeTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

    def test_parse_23_application1(self):
        fact = parse_cpe('cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*')
        self.assertIsInstance(fact, Product)
        self.assertEqual('openbsd', fact.get_vendor())
        self.assertEqual('openssh', fact.get_product())

    def test_parse_23_application2(self):
        fact = parse_cpe('cpe:2.3:a:openbsd:openssh:2.3p1:*:*:*:*:*:*:*')
        self.assertIsInstance(fact, Product)
        self.assertEqual('openbsd', fact.get_vendor())
        self.assertEqual('openssh', fact.get_product())
        self.assertEqual('2.3p1', fact.get_version())

    def test_parse_23_os1(self):
        fact = parse_cpe('cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*')
        self.assertIsInstance(fact, OperatingSystem)
        self.assertEqual('microsoft', fact.get_vendor())
        self.assertEqual('windows', fact.get_name())

    def test_parse_23_os2(self):
        fact = parse_cpe('cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*')
        self.assertIsInstance(fact, OperatingSystem)
        self.assertEqual('microsoft', fact.get_vendor())
        self.assertEqual('windows', fact.get_name())
        self.assertEqual('10', fact.get_version())

    def test_parse_1_application1(self):
        fact = parse_cpe('cpe:/a:redhat:docker')
        self.assertIsInstance(fact, Product)
        self.assertEqual('redhat', fact.get_vendor())
        self.assertEqual('docker', fact.get_product())

    def test_parse_1_application2(self):
        fact = parse_cpe('cpe:/a:apache:http_server:2.4.29')
        self.assertIsInstance(fact, Product)
        self.assertEqual('apache', fact.get_vendor())
        self.assertEqual('http_server', fact.get_product())
        self.assertEqual('2.4.29', fact.get_version())

    def test_parse_1_os1(self):
        fact = parse_cpe('cpe:/o:linux:linux_kernel')
        self.assertIsInstance(fact, OperatingSystem)
        self.assertEqual('linux', fact.get_vendor())
        self.assertEqual('linux_kernel', fact.get_name())

    def test_parse_1_os2(self):
        fact = parse_cpe('cpe:/o:microsoft:windows:10')
        self.assertIsInstance(fact, OperatingSystem)
        self.assertEqual('microsoft', fact.get_vendor())
        self.assertEqual('windows', fact.get_name())
        self.assertEqual('10', fact.get_version())


class ProductCpeTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

    def test_get_vendor_product(self):
        product = Product(vendor='openbsd', product='openssh')
        self.assertEqual('cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', product.get_cpe())

    def test_get_vendor_product_version(self):
        product = Product(vendor='openbsd', product='openssh', version='2.3p1')
        self.assertEqual('cpe:2.3:a:openbsd:openssh:2.3p1:*:*:*:*:*:*:*', product.get_cpe())

    def test_get_product_version(self):
        product = Product(product='openssh', version='2.3p1')
        self.assertEqual('cpe:2.3:a:*:openssh:2.3p1:*:*:*:*:*:*:*', product.get_cpe())


class OperatingSystemCpeTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

    def test_get_vendor_name(self):
        os = OperatingSystem(vendor='microsoft', name='windows')
        self.assertEqual('cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*', os.get_cpe())

    def test_get_vendor_name_version(self):
        os = OperatingSystem(vendor='microsoft', name='windows', version='10')
        self.assertEqual('cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*', os.get_cpe())

    def test_get_ostype_windows(self):
        os = OperatingSystem(os_type=OSTYPE_WINDOWS)
        self.assertEqual('cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*', os.get_cpe())

    def test_get_ostype_linux(self):
        os = OperatingSystem(os_type=OSTYPE_LINUX)
        self.assertEqual('cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*', os.get_cpe())

    def test_get_ostype_mac(self):
        os = OperatingSystem(os_type=OSTYPE_MAC)
        self.assertEqual('cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*', os.get_cpe())

    def test_get_ostype_version(self):
        os = OperatingSystem(os_type=OSTYPE_WINDOWS, version='10')
        self.assertEqual('cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*', os.get_cpe())

    def test_get_name_version(self):
        os = OperatingSystem(name='windows', version='10')
        self.assertEqual('cpe:2.3:o:*:windows:10:*:*:*:*:*:*:*', os.get_cpe())
