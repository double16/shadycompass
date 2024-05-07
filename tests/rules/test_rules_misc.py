from base import RulesBase
from shadycompass.facts import TargetDomain, WindowsDomain, \
    TlsCertificate
from tests.tests import assertFactIn


class MiscRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_windows_domain_target_domain(self):
        self.engine.declare(WindowsDomain(
            netbios_domain_name='SHADYCOMPASS',
            dns_domain_name='shadycompass.test',
            dns_tree_name='shadycompass.test',
        ))
        self.engine.run()
        assertFactIn(TargetDomain(domain='shadycompass.test'), self.engine)

    def test_tls_cert_target_domain(self):
        tls_cert = TlsCertificate(
            subjects=['DC', 'DC.shadycompass.test'],
            issuer='DC',
        )
        self.assertEqual('shadycompass.test', tls_cert.get_domain())
        self.assertEqual('DC.shadycompass.test', tls_cert.get_fqdn())
        self.engine.reset()
        self.engine.declare(tls_cert)
        self.engine.run()
        assertFactIn(TargetDomain(domain='shadycompass.test'), self.engine)
