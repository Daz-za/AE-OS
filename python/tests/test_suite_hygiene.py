"""The test suite itself: a test defined twice in one module silently replaces the first,
which then never runs. CI runs no Python linter, so this stands in for pyflakes' F811."""
import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parent


def test_no_test_module_defines_the_same_name_twice():
    shadowed = []
    for module in sorted(TESTS.glob("*.py")):
        seen = {}
        for node in ast.parse(module.read_text()).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name in seen:
                    shadowed.append(f"{module.name}:{node.lineno} {node.name} (first at line "
                                    f"{seen[node.name]})")
                seen.setdefault(node.name, node.lineno)
    assert shadowed == []
