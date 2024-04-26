from experta import Fact, KnowledgeEngine


def _is_match(fact: Fact, f1: Fact) -> bool:
    if type(fact) != type(f1):
        return False
    for k, v in fact.items():
        v1 = f1.get(k)
        if repr(v) != repr(v1):
            return False
    return True


def assertFactIn(fact: Fact, engine: KnowledgeEngine):
    for f1 in engine.facts.values():
        if _is_match(fact, f1):
            return
    raise AssertionError(f"{repr(fact)} not found in {engine.facts.values()}")


def assertFactNotIn(fact: Fact, engine: KnowledgeEngine):
    for f1 in engine.facts.values():
        if _is_match(fact, f1):
            raise AssertionError(f"{repr(fact)} found in {engine.facts.values()}")
