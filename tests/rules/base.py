import unittest
from typing import Union

from shadycompass import ShadyCompassEngine


class RulesBase(unittest.TestCase):

    def __init__(self, paths: Union[list[str], None], methodName: str = ...):
        super().__init__(methodName)
        if paths is None:
            paths = ['tests/fixtures/etchosts', 'tests/fixtures/nmap']
        self.engine = ShadyCompassEngine(paths)
        self.engine.reset()
        self.engine.update_facts()
        self.engine.run()
