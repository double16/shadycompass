from experta import Fact

from shadycompass.facts import FactReader, fact_reader_registry


class ZapSessionFactReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        # TODO: implement
        return []


fact_reader_registry.append(ZapSessionFactReader())
