import re

from experta import Fact

from shadycompass.config import ToolCategory
from shadycompass.facts import FactReader, check_file_signature, Username, fact_reader_registry, guess_target, \
    ScanPresent, EmailAddress

_SMTP_USER_ENUM_PATTERN = re.compile(r'(\S+)@([^@]+?):\s+Exists')
_SMTP_USER_ENUM_PORT_PATTERN = re.compile(r'Target TCP port[.\s]+(\d+)')


class SmtpUserEnumReader(FactReader):
    def read_facts(self, file_path: str) -> list[Fact]:
        if not check_file_signature(file_path, 'Starting smtp-user-enum '):
            return []
        print(f"[*] Reading smtp-user-enum findings from {file_path}")
        result = []
        targets = set()
        emails = set()
        port = 25
        with open(file_path, 'rt') as file:
            for line in file.readlines():
                m = _SMTP_USER_ENUM_PATTERN.search(line)
                if m:
                    username = m.group(1)
                    addrs = {}
                    target = guess_target(m.group(2))
                    if target:
                        targets.add(target)
                        if target.get('addr'):
                            addrs['addr'] = target.get('addr')
                        if target.get('hostname'):
                            addrs['hostname'] = target.get('hostname')
                            if '@' not in username:
                                emails.add(EmailAddress(email=f'{username}@{target.get('hostname')}'))
                    username_fact = Username(username=username, **addrs)
                    result.append(username_fact)
                    if '@' in username:
                        emails.add(EmailAddress(email=username))
                else:
                    m = _SMTP_USER_ENUM_PORT_PATTERN.search(line)
                    if m:
                        port = int(m.group(1))
        result.extend(emails)
        result.extend(targets)
        for target in targets:
            if target.get('addr'):
                result.append(ScanPresent(category=ToolCategory.smtp_scanner, name='smtp-user-enum',
                                          addr=target.get('addr'), port=port))
            if target.get('hostname'):
                result.append(ScanPresent(category=ToolCategory.smtp_scanner, name='smtp-user-enum',
                                          hostname=target.get('hostname'), port=port))

        return result


fact_reader_registry.append(SmtpUserEnumReader())
