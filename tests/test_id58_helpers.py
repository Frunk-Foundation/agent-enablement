import importlib
import sys
import uuid

from enabler_cli import id58 as cli_id58


def _lambda_id58():
    if "lambda" not in sys.path:
        sys.path.insert(0, "lambda")
    import id58 as mod

    return importlib.reload(mod)


def test_cli_id58_uuid4_shape():
    value = cli_id58.uuid4_base58_22()
    assert cli_id58.is_base58_22(value)


def test_cli_id58_zero_padding_contract():
    assert cli_id58.encode_16bytes_base58(b"\x00" * 16) == "1" * 22


def test_cli_uuid_text_to_base58_roundtrip():
    raw = uuid.uuid4()
    encoded = cli_id58.uuid_text_to_base58_22(str(raw))
    assert cli_id58.is_base58_22(encoded)
    assert encoded == cli_id58.encode_16bytes_base58(raw.bytes)


def test_lambda_id58_v4_shape():
    mod = _lambda_id58()
    value = mod.uuid4_base58_22()
    assert mod.is_base58_22(value)


def test_lambda_id58_v7_shape():
    mod = _lambda_id58()
    value = mod.uuid7_base58_22()
    assert mod.is_base58_22(value)


def test_lambda_uuid_text_to_base58_roundtrip():
    mod = _lambda_id58()
    raw = uuid.uuid4()
    encoded = mod.uuid_text_to_base58_22(str(raw))
    assert mod.is_base58_22(encoded)
    assert encoded == mod.encode_16bytes_base58(raw.bytes)
