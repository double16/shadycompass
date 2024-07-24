import json

import jsonschema
from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, http_url_targets, http_url, \
    VirtualHostname, ScanPresent

KATANA_SCHEMA = {
    "type": "object",
    "properties": {
        "timestamp": {"type": "string"},
        "request": {
            "type": "object",
            "properties": {
                "method": {"type": "string"},
                "endpoint": {"type": "string"},
                "tag": {"type": "string"},
            },
            "required": ["method", "endpoint"]
        },
    },
    "required": ["timestamp", "request"]
}

class KatanaReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, KATANA_SCHEMA):
            return []
        print(f"[*] Reading katana findings from {file_path}")
        result = []
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                try:
                    data = json.loads(line)
                    jsonschema.validate(instance=data, schema=KATANA_SCHEMA)
                    endpoint = data["request"]["endpoint"]
                    if '*' not in endpoint:
                        url_fact = http_url(endpoint)
                        result.append(url_fact)
                except (ValueError, jsonschema.exceptions.ValidationError):
                    pass
        result.extend(http_url_targets(result, infer_virtual_hosts=True))
        for virtual_hostname in filter(lambda e: isinstance(e, VirtualHostname), result):
            result.append(ScanPresent(category=ToolCategory.http_spider, name='katana',
                                      secure=virtual_hostname.is_secure(), port=virtual_hostname.get_port(),
                                      hostname=virtual_hostname.get_hostname(),
                                      url=virtual_hostname.get_url()))
        return result


fact_reader_registry.append(KatanaReader())
