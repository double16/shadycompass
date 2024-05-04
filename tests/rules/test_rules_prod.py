from shadycompass.config import SECTION_DEFAULT, OPTION_PRODUCTION
from shadycompass.facts import ProductionTarget
from tests.rules.base import RulesBase
from tests.tests import assertFactNotIn, assertFactIn


class ProductionTargetRulesTest(RulesBase):
    def __init__(self, methodName: str = ...):
        super().__init__(None, methodName)

    def test_default_non_prod(self):
        assertFactNotIn(ProductionTarget(), self.engine)

    def test_global_prod1(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ProductionTarget(), self.engine)

    def test_global_prod2(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'True', True)
        self.engine.run()
        assertFactIn(ProductionTarget(), self.engine)

    def test_global_non_prod1(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'false', True)
        self.engine.run()
        assertFactNotIn(ProductionTarget(), self.engine)

    def test_global_non_prod2(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'False', True)
        self.engine.run()
        assertFactNotIn(ProductionTarget(), self.engine)

    def test_local_prod1(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', False)
        self.engine.run()
        assertFactIn(ProductionTarget(), self.engine)

    def test_local_prod2(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'True', False)
        self.engine.run()
        assertFactIn(ProductionTarget(), self.engine)

    def test_local_non_prod1(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'false', False)
        self.engine.run()
        assertFactNotIn(ProductionTarget(), self.engine)

    def test_local_non_prod2(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'False', False)
        self.engine.run()
        assertFactNotIn(ProductionTarget(), self.engine)

    def test_local_override_global1(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'false', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', False)
        self.engine.run()
        assertFactIn(ProductionTarget(), self.engine)

    def test_local_override_global2(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'false', False)
        self.engine.run()
        assertFactNotIn(ProductionTarget(), self.engine)

    def test_global_retract(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.run()
        assertFactIn(ProductionTarget(), self.engine)
        self.engine.config_unset(SECTION_DEFAULT, OPTION_PRODUCTION, True)
        self.engine.run()
        assertFactNotIn(ProductionTarget(), self.engine)

    def test_local_retract(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', False)
        self.engine.run()
        assertFactIn(ProductionTarget(), self.engine)
        self.engine.config_unset(SECTION_DEFAULT, OPTION_PRODUCTION, False)
        self.engine.run()
        assertFactNotIn(ProductionTarget(), self.engine)

    def test_local_override_global_retract(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'false', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', False)
        self.engine.run()
        assertFactIn(ProductionTarget(), self.engine)
        self.engine.config_unset(SECTION_DEFAULT, OPTION_PRODUCTION, False)
        self.engine.run()
        assertFactNotIn(ProductionTarget(), self.engine)

    def test_local_override_retract(self):
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'true', True)
        self.engine.config_set(SECTION_DEFAULT, OPTION_PRODUCTION, 'false', False)
        self.engine.run()
        assertFactNotIn(ProductionTarget(), self.engine)
        self.engine.config_unset(SECTION_DEFAULT, OPTION_PRODUCTION, False)
        self.engine.run()
        assertFactIn(ProductionTarget(), self.engine)
