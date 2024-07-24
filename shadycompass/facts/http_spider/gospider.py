from experta import Fact

from shadycompass.facts import FactReader, fact_reader_registry


class GospiderReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        return []


fact_reader_registry.append(GospiderReader())