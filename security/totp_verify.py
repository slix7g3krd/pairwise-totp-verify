"""TOTP 二次验证（RFC 6238）及配套安全控制。

安全要点：
- 时间片基于 UTC epoch 秒（time.time()），不受本地时区/夏令时影响
- 校验窗口 ±window 个周期（默认 ±1），窗口外一律拒绝
- 重放缓存：同一个验证码全局只能消费一次（跨账号同样拒绝）
- 常量时间比较：先哈希再 compare_digest，长度不同也不提前返回
- 备份码支持哈希存储，消费即删除（一次性），加锁保证原子消费
- 锁定按 账号+IP 计数，达到阈值且在锁定期内拒绝
- 空密钥 / 空验证码直接拒绝
"""

import hashlib
import hmac
import struct
import threading
import time

_PERIOD = 30            # RFC 6238 默认时间步长（秒）
_DIGITS = 6             # 验证码位数
_MAX_ATTEMPTS = 5       # 锁定阈值
_LOCKOUT_SECONDS = 15 * 60  # 锁定时长

# 消费类操作（重放缓存、备份码）的互斥锁，保证并发下原子消费
_consume_lock = threading.Lock()


def _counter_for(timestamp, period=_PERIOD):
    """UTC epoch 秒 -> 时间片计数器（RFC 6238 的 T）。"""
    return int(timestamp) // period


def _hotp(secret, counter, digits=_DIGITS):
    """RFC 4226 HOTP：HMAC-SHA1 + 动态截断。"""
    key = secret.encode('utf-8') if isinstance(secret, str) else bytes(secret)
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def generate_totp(secret, timestamp=None, period=_PERIOD, digits=_DIGITS):
    """生成指定时刻的 TOTP 码；timestamp 缺省取 UTC 当前时间。"""
    if not secret:
        raise ValueError('secret must not be empty')
    if timestamp is None:
        timestamp = time.time()  # UTC epoch 秒，与本地时区/夏令时无关
    return _hotp(secret, _counter_for(timestamp, period), digits)


def constant_time_compare(a, b):
    """常量时间比较：先各自哈希，长度不同也不会提前返回。"""
    if a is None or b is None:
        return False
    a = a.encode('utf-8') if isinstance(a, str) else bytes(a)
    b = b.encode('utf-8') if isinstance(b, str) else bytes(b)
    da = hashlib.sha256(a).digest()
    db = hashlib.sha256(b).digest()
    return hmac.compare_digest(da, db)


def verify_totp(secret, code, timestamp=None, window=1, cache=None, user=None):
    """校验 TOTP 码。

    - 空密钥 / 空码直接拒绝
    - 接受当前及前后 window 个时间片的码
    - 传入 cache 时启用重放保护：同一码（含跨账号）只能成功一次，
      整个 命中检查+写入 在锁内完成，并发请求无法同时消费同一码
    """
    if not secret:
        return False
    if not code or not isinstance(code, str):
        return False
    if timestamp is None:
        timestamp = time.time()

    counter = _counter_for(timestamp)
    # 不提前 break：窗口内每个候选都做常量时间比较，避免时序泄露命中位置
    matched = False
    for offset in range(-window, window + 1):
        candidate = _hotp(secret, counter + offset)
        if constant_time_compare(candidate, code):
            matched = True
    if not matched:
        return False  # 码错

    if cache is not None:
        # 键只含码本身：同一码在任何账号下都只能消费一次
        with _consume_lock:
            if code in cache:
                return False  # 码已用过（与“码错”区分开，便于上层分类处理）
            cache[code] = {'user': user, 'counter': counter}
    return True


def consume_backup_code(store, user, code):
    """消费一次性备份码。存储支持哈希（sha256 十六进制）或明文键，命中即删除。"""
    if not code:
        return False
    codes = store.get(user)
    if not codes:
        return False
    hashed = hashlib.sha256(code.encode('utf-8')).hexdigest()
    with _consume_lock:
        for key in (hashed, code):
            if codes.get(key):
                del codes[key]  # 一次性：消费即删除，锁内完成防并发复用
                return True
    return False


def lockout_ok(store, user, ip, now=None):
    """按 账号+IP 判定是否允许继续尝试；达到阈值且在锁定期内则拒绝。"""
    if now is None:
        now = time.time()
    rec = store.get((user, ip)) or store.get(user)
    if not rec:
        return True
    attempts = rec.get('attempts', 0)
    last = rec.get('last', 0)
    if attempts >= _MAX_ATTEMPTS and (now - last) < _LOCKOUT_SECONDS:
        return False
    return True
