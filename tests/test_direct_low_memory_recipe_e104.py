import ast
import copy
from pathlib import Path
import unittest
from src.data import direct_low_memory_recipe_e104 as m


class Tests(unittest.TestCase):
    def plan(self):
        root=Path(__file__).resolve().parents[1]
        return m.original.compile_acceptance(
            (root/'data/manifests/ranking_v6_e85_input_observation_20261023_r1.json').read_bytes(),
            (root/'data/manifests/ranking_v6_e93_input_observation_20261023_r1.json').read_bytes(),
            m.original.E85_SHA256,m.original.E93_SHA256)

    def reseal(self,plan):
        body={k:v for k,v in plan.items() if k not in ('items','recipe_sha256')}
        body['items']=[{k:v for k,v in r.items() if k!='tcl_bytes'} for r in plan['items']]
        plan['recipe_sha256']=m.original.sha(m.original.canonical(body))

    def test_only_exact_command_removed_remaining_three_inputs_unchanged(self):
        source=self.plan();before=copy.deepcopy(source)
        result=m.transform(source)
        self.assertEqual(source,before)
        self.assertEqual([(r['circuit'],r['transition'],r['target_mode']) for r in result['items']],list(m.ROSTER))
        for row in result['items']:
            old=next(r for r in source['items'] if r['circuit']==row['circuit'] and r['transition']==row['transition'])
            self.assertEqual(row['tcl_bytes'],old['tcl_bytes'].replace(m.REMOVED,b'',1))
            self.assertEqual(row['tcl_sha256'],m.original.sha(row['tcl_bytes']))
            self.assertNotIn(b'add_processors',row['tcl_bytes'])
            self.assertEqual({k:v for k,v in row.items() if k not in ('tcl_bytes','tcl_sha256')},
                             {k:v for k,v in old.items() if k not in ('tcl_bytes','tcl_sha256')})
        self.assertFalse(result['memory_reduction_proven'])
        self.assertEqual(len(result['items']),3)
        self.assertNotEqual(source['recipe_sha256'],result['recipe_sha256'])

    def test_corrupt_base_hash_rejected(self):
        p=self.plan();p['recipe_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'BASE_RECIPE_CHANGED'):m.transform(p)

    def test_missing_or_duplicate_or_alias_processor_command_rejected(self):
        for changed in (b'',m.REMOVED*2,m.REMOVED+b'ADD_PROCESSORS localhost:2\n'):
            p=self.plan();row=p['items'][1]
            row['tcl_bytes']=row['tcl_bytes'].replace(m.REMOVED,changed)
            row['tcl_sha256']=m.original.sha(row['tcl_bytes']);self.reseal(p)
            with self.subTest(changed=changed),self.assertRaises(ValueError):m.transform(p)

    def test_reordered_base_roster_rejected(self):
        p=self.plan();p['items'].reverse();self.reseal(p)
        with self.assertRaisesRegex(ValueError,'BASE_ROSTER_CHANGED'):m.transform(p)

    def test_variant_recipe_hash_covers_new_serial_items(self):
        p=m.transform(self.plan());pin=p['recipe_sha256']
        body={k:v for k,v in p.items() if k not in ('items','recipe_sha256')}
        body['items']=[{k:v for k,v in r.items() if k!='tcl_bytes'} for r in p['items']]
        self.assertEqual(m.original.sha(m.original.canonical(body)),pin)

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))
