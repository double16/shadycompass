import json
from urllib.parse import urlparse

import jsonschema
from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, fact_reader_registry, check_file_signature, http_url, http_url_targets, \
    VirtualHostname, ScanPresent

GOSPIDER_SCHEMA = {
    "type": "object",
    "properties": {
        "input": {"type": "string"},
        "source": {"type": "string"},
        "type": {"type": "string"},
        "output": {"type": "string"},
    },
    "required": ["input", "source", "type", "output"]
}

class GospiderReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, GOSPIDER_SCHEMA):
            return []
        print(f"[*] Reading gospider findings from {file_path}")
        result = []
        subdomains = []
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                try:
                    data = json.loads(line)
                    jsonschema.validate(instance=data, schema=GOSPIDER_SCHEMA)
                    if data["type"] == "subdomain":
                        subdomains.append(VirtualHostname(
                            hostname=data["output"],
                            domain=urlparse(data["input"]).hostname
                        ))
                    else:
                        endpoint = data["output"]
                        if '://' in endpoint:
                            url_fact = http_url(endpoint)
                            result.append(url_fact)
                except (ValueError, jsonschema.exceptions.ValidationError):
                    pass
        result.extend(http_url_targets(result, infer_virtual_hosts=True))
        for virtual_hostname in filter(lambda e: isinstance(e, VirtualHostname), result):
            result.append(ScanPresent(category=ToolCategory.http_spider, name='gospider',
                                      secure=virtual_hostname.is_secure(), port=virtual_hostname.get_port(),
                                      hostname=virtual_hostname.get_hostname(),
                                      url=virtual_hostname.get_url()))
        result.extend(subdomains)
        return result


fact_reader_registry.append(GospiderReader())
