"""Single-worker scoped source loader, not an untrusted-code sandbox.

Expected hashes/order must come from independent packet review. All bytes are
verified before compile/registry changes. Use loaded functions only inside
the with block: restoring sys.modules is isolation, not revoking Python refs.
No transport or experiment dispatch is implemented here.
"""
import base64
from contextlib import contextmanager
import hashlib
import sys
import types

FROZEN_SOURCE_SHA256=None
FROZEN_SOURCE_ORDER=None
_ACTIVE=False


def require(ok,code):
    if not ok:raise ValueError(code)


def _hex(value):return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)


def verify(rows):
    pins,order=FROZEN_SOURCE_SHA256,FROZEN_SOURCE_ORDER
    require(type(pins) is dict and 1<=len(pins)<=96 and all(type(name) is str and 0<len(name)<=128 and
        all(c in 'abcdefghijklmnopqrstuvwxyz0123456789_' for c in name) and _hex(pin) for name,pin in pins.items()) and
        type(order) is tuple and len(order)==len(pins) and all(type(name) is str for name in order) and
        len(set(order))==len(order) and set(order)==set(pins),'E138_SOURCE_FREEZE_REQUIRED')
    require(type(rows) is list and len(rows)==len(order),'E138_SOURCE_ROSTER')
    decoded=[];total=0
    for row,name in zip(rows,order):
        require(type(row) is dict and set(row)=={'name','sha256','body_base64'} and row['name']==name and
            row['sha256']==pins[name] and type(row['body_base64']) is str and len(row['body_base64'])<=349528,
            'E138_SOURCE_EXACT_ORDERED_ROW')
        raw=base64.b64decode(row['body_base64'],validate=True);total+=len(raw)
        require(0<len(raw)<=262144 and total<=4194304 and hashlib.sha256(raw).hexdigest()==pins[name],
            'E138_SOURCE_BODY_PIN_OR_BOUND')
        decoded.append((name,raw,pins[name]))
    return decoded


def _is_source(name):return name=='src' or name.startswith('src.')


@contextmanager
def source_session(rows):
    global _ACTIVE
    require(not _ACTIVE,'E138_SOURCE_SESSION_NONREENTRANT')
    decoded=verify(rows)
    # Compilation is also completed before changing any cached module.
    compiled=[(name,compile(raw,'<e138-reviewed-'+name+'>','exec'),pin) for name,raw,pin in decoded]
    saved={name:module for name,module in sys.modules.items() if _is_source(name)}
    _ACTIVE=True
    try:
        for name in list(sys.modules):
            if _is_source(name):del sys.modules[name]
        for name in ('src','src.data'):
            module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
            if name=='src.data':sys.modules['src'].data=module
        loaded={}
        for name,code,pin in compiled:
            module=types.ModuleType('src.data.'+name);module.__package__='src.data'
            sys.modules[module.__name__]=module;setattr(sys.modules['src.data'],name,module)
            exec(code,module.__dict__)
            module.__source_sha256__=pin;loaded[name]=module
        yield loaded
    finally:
        for name in list(sys.modules):
            if _is_source(name):del sys.modules[name]
        sys.modules.update(saved)
        _ACTIVE=False
