from experta import Fact, KnowledgeEngine


def _is_match(fact: Fact, f1: Fact) -> bool:
    if type(fact) != type(f1):
        return False
    for k, v in fact.items():
        v1 = f1.get(k)
        if repr(v) != repr(v1):
            return False
    return True


def assertFactIn(fact: Fact, engine: KnowledgeEngine, times: int = 1):
    assert times > 0
    count = 0
    for f1 in engine.facts.values():
        if _is_match(fact, f1):
            count += 1
    if count == 0:
        raise AssertionError(f"{repr(fact)} not found in {engine.facts.values()}")
    elif times != count:
        raise AssertionError(f"{repr(fact)} found {count} times (expected {times}) in {engine.facts.values()}")


def assertFactNotIn(fact: Fact, engine: KnowledgeEngine):
    for f1 in engine.facts.values():
        if _is_match(fact, f1):
            raise AssertionError(f"{repr(fact)} found in {engine.facts.values()}")
