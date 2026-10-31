"""Execute bootstrap only in an in-process fake stdin/argv environment."""
import ast
import base64
import copy
import io
from pathlib import Path
import shlex
import sys
import types
import unittest
from unittest import mock
from scripts import e138_reviewed_envelope as m


class Tests(unittest.TestCase):
    def boot(self,raw,arg=None,role='capture'):
        argument=arg if arg is not None else m.canonical(m.intent(role,m.sha(raw)))
        namespace={}
        with mock.patch.object(sys,'argv',['bootstrap',base64.b64encode(argument).decode('ascii')]),\
                mock.patch.object(sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(raw))),\
                mock.patch('subprocess.Popen') as spawn:
            exec(compile(m.BOOTSTRAP,'<test-bootstrap>','exec'),namespace)
        spawn.assert_not_called()
        return namespace

    def test_bootstrap_validates_payload_before_execution(self):
        payload=b'CAPTURED=(__payload_sha256__,dict(__role_intent__),__connection_start__)'
        ns=self.boot(payload)
        self.assertEqual(ns['CAPTURED'][0],m.sha(payload));self.assertEqual(ns['CAPTURED'][1]['role'],'capture')
        self.assertGreaterEqual(ns['CAPTURED'][2],0.)
        with self.assertRaisesRegex(ValueError,'PAYLOAD_CHANGED'):
            self.boot(payload,m.canonical(m.intent('capture','d'*64)))

    def test_exact_canonical_and_duplicate_keys_and_bool_debit(self):
        payload=b'VALUE=1';good=m.canonical(m.intent('capture',m.sha(payload)))
        bad=[b' '+good,good[:-1]+b',"role":"capture"}',good.replace(b'"role_index":1',b'"role_index":true'),
            good.replace(b'"automatic_retries":0',b'"automatic_retries":1')]
        for arg in bad:
            with self.assertRaises(ValueError):self.boot(payload,arg)

    def test_invocation_has_no_self_hash_cycle_or_transport(self):
        payload=b'VALUE=1';plan=m.invocation('execution',payload)
        argv=shlex.split(plan['remote_command']);self.assertEqual(argv[:5],['/usr/bin/python3','-I','-S','-B','-c'])
        self.assertEqual(argv[5],m.BOOTSTRAP)
        self.assertIn(m.sha(payload).encode('ascii'),base64.b64decode(argv[6]))
        self.assertFalse(plan['execution_ready']);self.assertNotIn(m.sha(payload).encode('ascii'),payload)

    def template(self,role='capture'):
        package=dict(authority=b'synthetic authority',proposal=b'synthetic proposal')
        if role=='execution':package['policy']=b'synthetic policy'
        template=dict(role=role,loader_sha256='a'*64,source_sha256={'module':'b'*64},source_order=('module',),
            input_sha256={k:m.sha(raw) for k,raw in package.items()},authorization_sha256=m.sha(package['authority']),
            proposal_sha256=m.sha(package['proposal']),assembly=None)
        if role=='execution':
            template['assembly']={key:copy.deepcopy(template[key]) for key in m.ASSEMBLY_KEYS if key!='policy_sha256'}
            template['assembly']['policy_sha256']=m.sha(package['policy'])
        return template,package

    def test_only_allowlisted_derived_fields_and_no_mutation(self):
        for role in m.ROLES:
            template,package=self.template(role);before=copy.deepcopy(template)
            frozen,result=m.derive(template,package,m.intent(role,'c'*64),'c'*64)
            self.assertEqual(template,before);self.assertNotIn('role2_intent',package)
            self.assertEqual(frozen['payload_sha256'],'c'*64)
            self.assertEqual(frozen['source_sha256'],template['source_sha256'])
            self.assertEqual(frozen['source_order'],template['source_order'])
            if role=='execution':
                self.assertEqual(frozen['assembly']['payload_sha256'],'c'*64)
                self.assertEqual(frozen['input_sha256']['role2_intent'],m.sha(result['role2_intent']))
                self.assertEqual(frozen['assembly']['input_sha256'],frozen['input_sha256'])
            else:self.assertEqual(result,package)

    def test_static_inputs_cannot_be_relearned_or_intent_injected(self):
        template,package=self.template('execution')
        for bad in (dict(package,authority=b'changed'),dict(package,role2_intent=b'forged')):
            with self.assertRaisesRegex(ValueError,'STATIC_INPUT_PIN'):m.derive(template,bad,m.intent('execution','c'*64),'c'*64)
        template['assembly']['policy_sha256']='c'*64
        with self.assertRaisesRegex(ValueError,'STATIC_ASSEMBLY_JOIN'):
            m.derive(template,package,m.intent('execution','c'*64),'c'*64)
        template['assembly']['policy_sha256']=m.sha(package['policy'])
        # Other source/input bindings may not be changed in the assembly.
        template['assembly']['source_sha256']={'module':'d'*64}
        with self.assertRaisesRegex(ValueError,'STATIC_ASSEMBLY_JOIN'):
            m.derive(template,package,m.intent('execution','c'*64),'c'*64)

    def test_cross_role_intent_and_extra_dynamic_freeze_rejected(self):
        template,package=self.template()
        with self.assertRaisesRegex(ValueError,'VERIFIED_INVOCATION'):
            m.derive(template,package,m.intent('execution','c'*64),'c'*64)
        template['payload_sha256']='c'*64
        with self.assertRaisesRegex(ValueError,'STATIC_TEMPLATE'):
            m.derive(template,package,m.intent('capture','c'*64),'c'*64)

    def test_python36_syntax_and_bootstrap_bound(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))
        ast.parse(m.BOOTSTRAP,feature_version=(3,6))
        with self.assertRaises(ValueError):m.invocation('capture',b'x'*(m.MAX_PAYLOAD+1))
        with self.assertRaisesRegex(ValueError,'PAYLOAD_BOUND'):self.boot(b'')


if __name__=='__main__':unittest.main()
