import json

import jsonschema
from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, http_url_targets, http_url

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
        result.extend(http_url_targets(
            result,
            infer_virtual_hosts=True,
            infer_scan_category_tool_name=(ToolCategory.http_spider, 'katana')
        ))
        return result


fact_reader_registry.append(KatanaReader())
