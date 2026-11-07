"""The test suite itself: a test defined twice in one module or one class silently replaces
the first, which then never runs. CI runs no Python linter, so this stands in for pyflakes'
F811."""
import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parent
DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _shadowed(where, body):
    out, seen = [], {}
    for node in body:
        if isinstance(node, DEFINITIONS):
            if node.name in seen:
                out.append(f"{where}:{node.lineno} {node.name} (first at line "
                           f"{seen[node.name]})")
            seen.setdefault(node.name, node.lineno)
        if isinstance(node, ast.ClassDef):
            out += _shadowed(f"{where} {node.name}", node.body)
    return out


def test_no_test_module_or_class_defines_the_same_name_twice():
    shadowed = []
    for module in sorted(TESTS.glob("*.py")):
        shadowed += _shadowed(module.name, ast.parse(module.read_text()).body)
    assert shadowed == []


def test_the_check_sees_a_method_defined_twice_in_a_class():
    tree = ast.parse("class T:\n    def test_a(self): pass\n    def test_a(self): pass\n")
    assert _shadowed("m.py", tree.body) == ["m.py T:3 test_a (first at line 2)"]
