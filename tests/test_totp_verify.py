import pytest

from security.totp_verify import (
    generate_totp,
    verify_totp,
    constant_time_compare,
    consume_backup_code,
    lockout_ok
)


def test_length():
    assert len(generate_totp('secret', 59)) == 6

def test_current():
    code = generate_totp('secret', 59)
    assert verify_totp('secret', code, 59, 0) is True

def test_previous_window():
    code = generate_totp('secret', 30)
    assert verify_totp('secret', code, 59, 1) is True

def test_outside_window():
    code = generate_totp('secret', 0)
    assert verify_totp('secret', code, 120, 1) is False

def test_wrong_code():
    assert verify_totp('secret', '000000', 59, 0) is False

def test_replay_first():
    cache = {}
    code = generate_totp('secret', 59)
    assert verify_totp('secret', code, 59, 0, cache, 'u') is True

def test_replay_second():
    cache = {}
    code = generate_totp('secret', 59)
    assert verify_totp('secret', code, 59, 0, cache, 'u') is True
    assert verify_totp('secret', code, 59, 0, cache, 'u') is False

def test_empty_code():
    assert verify_totp('secret', '', 59) is False

def test_constant_true():
    assert constant_time_compare('abc', 'abc') is True

def test_constant_false():
    assert constant_time_compare('abc', 'abd') is False

def test_backup_first():
    store = {'u': {'b1': True}}
    assert consume_backup_code(store, 'u', 'b1') is True

def test_backup_second():
    store = {'u': {'b1': True}}
    assert consume_backup_code(store, 'u', 'b1') is True
    assert consume_backup_code(store, 'u', 'b1') is False

def test_lockout():
    store = {'u': {'attempts': 5, 'last': 0}}
    assert lockout_ok(store, 'u', '1.2.3.4', 1) is False

def test_unknown_user():
    assert lockout_ok({}, 'u', '1.2.3.4', 1) is True

def test_invalid_secret():
    assert verify_totp('', '123456', 59) is False
