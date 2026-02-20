import importlib
import sys


def _load_module():
    if "lambda" not in sys.path:
        sys.path.insert(0, "lambda")
    import profile_codec as module

    return importlib.reload(module)


def test_ddb_str_list_supports_string_set():
    m = _load_module()
    item = {"groups": {"SS": ["ops", "dev", "ops", ""]}}
    assert m.ddb_str_list(item, "groups") == ["ops", "dev"]

def test_ddb_str_list_rejects_non_string_set_shapes():
    m = _load_module()
    assert m.ddb_str_list({"groups": {"L": [{"S": "ops"}]}}, "groups") == []
    assert m.ddb_str_list({"groups": {"S": "ops,dev"}}, "groups") == []
