"""Pure E138 invocation/derived-freeze helpers; no IO or transport.

The trusted controller must review BOTH complete payload and exact command.
SHA arguments alone do not authenticate a sender. Keeping command arguments
outside the payload avoids embedding a payload's own hash inside itself.
Only payload hash and exact canonical role2 intent may be runtime-derived.
"""
import base64
import copy
import hashlib
import json
import shlex

MAX_PAYLOAD=4194304
ROLES=('capture','execution')
STATIC_KEYS=frozenset(('role','loader_sha256','source_sha256','source_order','input_sha256',
    'authorization_sha256','proposal_sha256','assembly'))
ASSEMBLY_KEYS=frozenset(('authorization_sha256','proposal_sha256','policy_sha256','input_sha256',
    'source_sha256','source_order'))


def require(ok,code):
    if not ok:raise ValueError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def _hex(value):return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)


def intent(role,payload_sha):
    require(role in ROLES and _hex(payload_sha),'E138_ENVELOPE_ROLE_OR_PAYLOAD')
    return dict(role=role,attempt_consumed=True,role_index=ROLES.index(role)+1,connections_max=3,
        automatic_retries=0,payload_sha256=payload_sha)


# This exact script is included in the independently reviewed invocation hash.
# It never reads environment/scripts beyond stdin or starts a child process.
BOOTSTRAP='''import time
__connection_start__=time.monotonic()
import sys,base64,hashlib,json
if len(sys.argv)!=2 or type(sys.argv[1]) is not str or len(sys.argv[1])>5464:raise ValueError("E138_BOOT_ARGUMENT")
arg=base64.b64decode(sys.argv[1],validate=True)
if len(arg)>4096:raise ValueError("E138_BOOT_ARGUMENT_BOUND")
__role_intent__=json.loads(arg.decode("ascii"))
if type(__role_intent__) is not dict or set(__role_intent__)!={"role","attempt_consumed","role_index","connections_max","automatic_retries","payload_sha256"}:raise ValueError("E138_BOOT_INTENT")
i=__role_intent__
if i["role"] not in ("capture","execution"):raise ValueError("E138_BOOT_ROLE")
if i["attempt_consumed"] is not True or type(i["role_index"]) is not int or i["role_index"]!=("capture","execution").index(i["role"])+1 or type(i["connections_max"]) is not int or i["connections_max"]!=3 or type(i["automatic_retries"]) is not int or i["automatic_retries"]!=0:raise ValueError("E138_BOOT_DEBIT")
if type(i["payload_sha256"]) is not str or len(i["payload_sha256"])!=64 or any(c not in "0123456789abcdef" for c in i["payload_sha256"]):raise ValueError("E138_BOOT_EXPECTED_HASH")
if json.dumps(i,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")!=arg:raise ValueError("E138_BOOT_CANONICAL_INTENT")
raw=sys.stdin.buffer.read(4194305)
if type(raw) is not bytes or not 0<len(raw)<=4194304:raise ValueError("E138_BOOT_PAYLOAD_BOUND")
__payload_sha256__=hashlib.sha256(raw).hexdigest()
if __payload_sha256__!=i["payload_sha256"]:raise ValueError("E138_BOOT_PAYLOAD_CHANGED")
exec(compile(raw,"<e138-reviewed-payload>","exec"),globals())
'''


def remote_command(role,payload_sha):
    argument=base64.b64encode(canonical(intent(role,payload_sha))).decode('ascii')
    return '/usr/bin/python3 -I -S -B -c '+shlex.quote(BOOTSTRAP)+' '+shlex.quote(argument)


def invocation(role,payload):
    require(type(payload) is bytes and 0<len(payload)<=MAX_PAYLOAD,'E138_ENVELOPE_PAYLOAD_BOUND')
    digest=sha(payload);command=remote_command(role,digest)
    return dict(role=role,payload_sha256=digest,remote_command=command,
        invocation_sha256=sha(canonical(dict(remote_command=command,payload_sha256=digest))),
        bootstrap_sha256=sha(BOOTSTRAP.encode('ascii')),execution_ready=False)


def derive(template,package,verified_intent,verified_payload_sha):
    """Template bytes are a reviewed static payload constant, NOT wire config.

    verified_* must come from the exact reviewed BOOTSTRAP execution. This pure
    helper does not authenticate that provenance and cannot release execution.
    """
    require(type(template) is dict and set(template)==STATIC_KEYS and template['role'] in ROLES and
        all(_hex(template[k]) for k in ('loader_sha256','authorization_sha256','proposal_sha256')) and
        type(template['source_sha256']) is dict and 1<=len(template['source_sha256'])<=96 and
        all(type(k) is str and _hex(v) for k,v in template['source_sha256'].items()) and
        type(template['source_order']) is tuple and
        all(type(name) is str for name in template['source_order']) and
        len(set(template['source_order']))==len(template['source_order'])==len(template['source_sha256']) and
        set(template['source_order'])==set(template['source_sha256']) and
        type(template['input_sha256']) is dict and all(type(k) is str and _hex(v) for k,v in template['input_sha256'].items()),
        'E138_ENVELOPE_STATIC_TEMPLATE')
    require(type(verified_intent) is dict and canonical(verified_intent)==canonical(intent(template['role'],verified_payload_sha)) and
        all(type(verified_intent[k]) is int for k in ('role_index','connections_max','automatic_retries')),
        'E138_ENVELOPE_VERIFIED_INVOCATION')
    require(type(package) is dict and set(package)==set(template['input_sha256']) and
        'role2_intent' not in package and {'authority','proposal'}<=set(package) and
        all(type(raw) is bytes and len(raw)<=6291456 and sha(raw)==template['input_sha256'][key] for key,raw in package.items()) and
        sum(map(len,package.values()))<=10485760 and
        sha(package['authority'])==template['authorization_sha256'] and sha(package['proposal'])==template['proposal_sha256'],
        'E138_ENVELOPE_STATIC_INPUT_PIN')
    frozen=copy.deepcopy(template);result=dict(package)
    frozen['payload_sha256']=verified_payload_sha
    if template['role']=='capture':
        require(set(package)=={'authority','proposal'} and template['assembly'] is None,'E138_ENVELOPE_CAPTURE_SHAPE')
    else:
        assembly=template['assembly']
        require(type(assembly) is dict and set(assembly)==ASSEMBLY_KEYS and _hex(assembly['policy_sha256']) and
            'policy' in package and sha(package['policy'])==assembly['policy_sha256'] and
            all(assembly[key]==template[key] for key in ASSEMBLY_KEYS-{'policy_sha256'}),
            'E138_ENVELOPE_STATIC_ASSEMBLY_JOIN')
        result['role2_intent']=canonical(verified_intent)
        frozen['input_sha256']['role2_intent']=sha(result['role2_intent'])
        frozen['assembly']['payload_sha256']=verified_payload_sha
        frozen['assembly']['input_sha256']['role2_intent']=sha(result['role2_intent'])
    return frozen,result
