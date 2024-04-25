import os.path
from configparser import ConfigParser

from experta import KnowledgeEngine

from shadycompass.config import ConfigFact, get_local_config_path, \
    get_global_config_path
from shadycompass.facts import fact_reader_registry
from shadycompass.facts.filemetadata import FileMetadataCache
import shadycompass.facts.all  # noqa: F401
from shadycompass.rules.all import AllRules


class ShadyCompassEngine(
    KnowledgeEngine,
    AllRules,
):
    def __init__(self, paths: list[str] = None):
        super().__init__()
        if paths is None:
            paths = [os.getcwd()]
        for fact_reader in fact_reader_registry:
            paths.extend(fact_reader.files())
        self.file_metadata = FileMetadataCache(paths)

    def update_facts(self):
        retract_queue = []
        for file_path in self.file_metadata.find_changes():
            if os.path.exists(file_path):
                for fact_reader in fact_reader_registry:
                    the_facts = fact_reader.read_facts(file_path)
                    for the_fact in the_facts:
                        the_fact.update({'file_path': file_path})
                        self.declare(the_fact)
            else:
                # retract facts for files that have been removed
                for fact in self.facts.values():
                    if fact.get('file_path') == file_path:
                        retract_queue.append(fact)
        for fact in retract_queue:
            self.retract(fact)

    def _save_config(self, facts: list[ConfigFact], config_path: str):
        config = ConfigParser()
        for fact in facts:
            section = str(fact.get('section'))
            if not config.has_section(section):
                config.add_section(section)
            config.set(section, str(fact.get('option')), str(fact.get('value')))
        with open(config_path, 'w') as file:
            config.write(file)

    def save_config(self):
        local_configs = list()
        global_configs = list()
        for fact in filter(lambda f: isinstance(f, ConfigFact), self.facts.values()):
            if fact.get('global0'):
                global_configs.append(fact)
            else:
                local_configs.append(fact)
        self._save_config(local_configs, get_local_config_path())
        self._save_config(global_configs, get_global_config_path())
