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


def _get_facts_by_type(fact: Fact, engine: KnowledgeEngine) -> list[Fact]:
    # return engine.facts.values()
    def by_type(e: Fact) -> bool:
        return isinstance(e, type(fact))

    def by_type_and_category(e: Fact) -> bool:
        return isinstance(e, type(fact)) and e.get('category') == fact.get('category')

    if fact.get('category') is not None:
        return list(filter(by_type_and_category, engine.facts.values()))

    return list(filter(by_type, engine.facts.values()))


def _facts_str(facts: Iterable[Fact]) -> str:
    return '\n'.join(map(lambda e: repr(e), facts))


def assertFactIn(fact: Fact, engine: KnowledgeEngine, times: int = 1):
    assert times > 0
    count = 0
    for f1 in engine.facts.values():
        if _is_match(fact, f1):
            count += 1
    if count == 0:
        raise AssertionError(f"{repr(fact)} not found in:\n{_facts_str(_get_facts_by_type(fact, engine))}")
    elif times != count:
        raise AssertionError(
            f"{repr(fact)} found {count} times (expected {times}) in:\n{_facts_str(_get_facts_by_type(fact, engine))}")


def assertFactNotIn(fact: Fact, engine: KnowledgeEngine):
    for f1 in engine.facts.values():
        if _is_match(fact, f1):
            raise AssertionError(f"{repr(fact)} found in:\n{_facts_str(_get_facts_by_type(fact, engine))}")
