# A CPython smoke test, run under the emulator and diffed against the same
# interpreter running natively.
#
# Every line exercises something the emulator had to get right to get here: the
# import machinery reading real .pyc files, C extension modules compiled into
# python3xx.dll, the string and integer implementations, floating point, and the
# filesystem.  A single differing character means something underneath is wrong.
import base64
import collections
import functools
import hashlib
import itertools
import json
import math
import os
import re
import sys

print("version", sys.version_info[:3])
print("maxsize", sys.maxsize)

print("math", round(math.sqrt(2), 12), round(math.sin(1), 12), math.factorial(15))
print("bigint", 2 ** 200, pow(3, 100, 1000000007))
print("float", 1 / 3, 1e300 * 10, float("nan") != float("nan"))

print("json", json.dumps({"b": [1, 2, 3], "a": "x", "c": None}, sort_keys=True))
print("sha256", hashlib.sha256(b"x86 emulator").hexdigest())
print("md5", hashlib.md5(b"hello").hexdigest())
print("base64", base64.b64encode(b"x86 emulator").decode())

Point = collections.namedtuple("Point", "x y")
p = Point(3, 4)
print("namedtuple", p, math.hypot(*p))
print("counter", sorted(collections.Counter("mississippi").items()))


@functools.lru_cache(maxsize=None)
def fib(n):
    return n if n < 2 else fib(n - 1) + fib(n - 2)


print("fib", fib(60))
print("regex", re.findall(r"(\w+)=(\d+)", "a=1 bb=22 ccc=333"))
print("sub", re.sub(r"\s+", "_", "  collapse   these  spaces "))
print("accumulate", list(itertools.accumulate(range(1, 9))))
print("sorted", sorted({"pear": 2, "apple": 1, "fig": 3}.items(), key=lambda kv: -kv[1]))
print("format", f"{math.pi:.6f} {255:#x} {-7:+d} {'mid':^9}|")

path = "x86emu_python_test.tmp"
with open(path, "w", encoding="utf-8") as f:
    f.write("first\nsecond\nthird\n")
with open(path, encoding="utf-8") as f:
    print("lines", [line.strip() for line in f])
print("size", os.path.getsize(path))
os.remove(path)
print("gone", os.path.exists(path))

try:
    {}["missing"]
except KeyError as e:
    print("caught", type(e).__name__, e)

print("done")
