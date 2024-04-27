import unittest

from shadycompass.facts.http_buster.feroxbuster import FeroxbusterReader
from shadycompass.facts import HttpUrl


class FeroxbusterReaderTest(unittest.TestCase):

    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        self.reader = FeroxbusterReader()

    def test_facts(self):
        facts = self.reader.read_facts('tests/fixtures/feroxbuster/ferox-443-dirs.txt')
        self.assertEqual(639, len(facts))
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb/program/js/jstz.min.js'), facts)
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb/skins/elastic/images/favicon.ico'), facts)
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb/skins/elastic/images/logo.svg'), facts)
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb/skins/elastic/watermark.html'), facts)
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb/plugins/jqueryui/themes/elastic/jquery-ui.min.css'), facts)
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb/program/js/jquery.min.js'), facts)
        self.assertIn(HttpUrl(port=443, vhost='hospital.htb', url='https://hospital.htb/skins/elastic/deps/bootstrap.bundle.min.js'), facts)
