from typing import Iterable

from experta import Fact, KnowledgeEngine


def _is_match(fact: Fact, f1: Fact) -> bool:
    if type(fact) != type(f1):
        return False
    for k, v in fact.items():
        v1 = f1.get(k)
        if repr(v) != repr(v1):
            return False
    return True


def _get_facts_by_type(fact: Fact, facts: list[Fact]) -> list[Fact]:
    # return engine.facts.values()
    def by_type(e: Fact) -> bool:
        return isinstance(e, type(fact))

    def by_type_and_category(e: Fact) -> bool:
        return isinstance(e, type(fact)) and e.get('category') == fact.get('category')

    if fact.get('category') is not None:
        return list(filter(by_type_and_category, facts))

    return list(filter(by_type, facts))


def _facts_str(facts: Iterable[Fact]) -> str:
    return '\n'.join(map(lambda e: repr(e), facts))


def assertFactIn(fact: Fact, facts_source, times: int = 1):
    if isinstance(facts_source, KnowledgeEngine):
        facts = facts_source.facts.values()
    else:
        facts = facts_source
    assert times > 0
    count = 0
    for f1 in facts:
        if _is_match(fact, f1):
            count += 1
    if count == 0:
        raise AssertionError(f"{repr(fact)} not found in:\n{_facts_str(_get_facts_by_type(fact, facts))}")
    elif times != count:
        raise AssertionError(
            f"{repr(fact)} found {count} times (expected {times}) in:\n{_facts_str(_get_facts_by_type(fact, facts))}")


def assertFactNotIn(fact: Fact, facts_source):
    if isinstance(facts_source, KnowledgeEngine):
        facts = facts_source.facts.values()
    else:
        facts = facts_source
    for f1 in facts:
        if _is_match(fact, f1):
            raise AssertionError(f"{repr(fact)} found in:\n{_facts_str(_get_facts_by_type(fact, facts))}")
