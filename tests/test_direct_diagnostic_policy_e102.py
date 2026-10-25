"""Synthetic command envelopes around exact observed diagnostic messages."""
import ast
import json
from pathlib import Path
import unittest
from src.data import direct_diagnostic_policy_e102 as m

FIXTURE = json.loads("{\"library_block\":\"//  Warning: read_verilog must be used to read in modules (or read_cell_library to read in models)\\n//    to attach the attribute-only model attributes to if the attributes are required for\\n//    the tessent flow being comtemplated.\\n//    No match for Cell (or model_attributes model) names which follow.\\n//    As a result, none of their cell or pin attributes were used.\\n//     All model attributes are from file '/home/jiangchuanc/Desktop/work/SCC28NHK_HSC31_LVT_V0p1/liberty/0.8v/scc28nhk_hsc31_lvt_scan.tcelllib'.\\n//      'FDCAP128_9TL31' on line 53.\\n//      'FDCAP16_9TL31' on line 59.\\n//      'FDCAP2_9TL31' on line 65.\\n//      'FDCAP32_9TL31' on line 71.\\n//      'FDCAP3_9TL31' on line 77.\\n//      'FDCAP4_9TL31' on line 83.\\n//      'FDCAP5_9TL31' on line 89.\\n//      'FDCAP64_9TL31' on line 95.\\n//      'FDCAP6_9TL31' on line 101.\\n//      'FDCAP8_9TL31' on line 107.\",\"examples\":{\"aes_core_H_TO_M\":[\"//  Warning: Rule FN1 violation occurs 6 times\",\"//  Warning: Rule FN4 violation occurs 637 times\",\"//  Warning: 16 edge-triggered clock ports set to stable high. (D7)\",\"//  Warning: EDT initialization cycles increase each pattern size by 26%.\"],\"aes_core_H_TO_F\":[\"//  Warning: Rule FN1 violation occurs 6 times\",\"//  Warning: Rule FN4 violation occurs 541 times\",\"//  Warning: 4 edge-triggered clock ports set to stable high. (D7)\"],\"spi_H_TO_M\":[\"//  Warning: Rule FN1 violation occurs 7 times\",\"//  Warning: Rule FN4 violation occurs 336 times\",\"//  Warning: 16 edge-triggered clock ports set to stable high. (D7)\",\"//  Warning: EDT initialization cycles increase each pattern size by 60%.\"],\"spi_H_TO_F\":[\"//  Warning: Rule FN1 violation occurs 7 times\",\"//  Warning: Rule FN4 violation occurs 240 times\",\"//  Warning: 4 edge-triggered clock ports set to stable high. (D7)\"]}}")


class Tests(unittest.TestCase):
    def envelope(self,circuit='aes_core',transition='H_TO_M'):
        tcl=(b'read_cell_library {fixed-library}\nread_design fixed -design_identifier fixed\n'
             b'read_faults {fixed-common}\nread_faults {fixed-translated} -merge -show_warnings\n')
        warnings=(FIXTURE['library_block']+'\n//  ---------------------------------------------------------------------------\n'+
                  '\n'.join(FIXTURE['examples'][circuit+'_'+transition])+'\n').encode('ascii')
        marker=('E94_TRANSLATED_STATUS_ACCEPTANCE=PASS '+circuit+' '+transition).encode('ascii')
        cmds=tcl.splitlines()
        log=b'\n'.join(b'//  command: '+x for x in cmds[:2])+b'\n'+warnings+b'\n'.join(
            b'//  command: '+x for x in cmds[2:])+b'\n'+marker+b'\n'
        return log,marker,circuit,transition,tcl

    def test_exact_four_profiles_are_only_import_execution_acceptance(self):
        for circuit in ('aes_core','spi'):
            for transition in ('H_TO_M','H_TO_F'):
                with self.subTest(circuit=circuit,transition=transition):
                    value=m.evaluate(*self.envelope(circuit,transition))
                    self.assertTrue(value['passed'],value)
                    self.assertFalse(value['d95_verified'])
                    self.assertFalse(value['fault_semantics_verified'])
                    self.assertTrue(all(not w['quality_harmlessness_proven']
                                        for w in value['startup_exceptions']))

    def test_multiline_library_path_or_model_change_is_rejected(self):
        for old,new in ((b'/Desktop/work/',b'/Desktop/other/'),(b'FDCAP128_9TL31',b'OTHER_MODEL')):
            args=list(self.envelope());args[0]=args[0].replace(old,new)
            self.assertFalse(m.evaluate(*args)['passed'])

    def test_variant_unknown_duplicate_and_post_import_warning_rejected(self):
        for action in ('variant','unknown','duplicate','post'):
            args=list(self.envelope())
            if action=='variant':args[0]=args[0].replace(b'occurs 6 times',b'occurs 7 times')
            if action=='unknown':args[0]=b'// Warning: surprise\n'+args[0]
            if action=='duplicate':args[0]=b'//  Warning: Rule FN1 violation occurs 6 times\n'+args[0]
            if action=='post':
                line=b'//  Warning: Rule FN1 violation occurs 6 times\n'
                args[0]=args[0].replace(line,b'').replace(args[1],line+args[1])
            with self.subTest(action=action):
                self.assertFalse(m.evaluate(*args)['passed'])

    def test_two_exact_paths_parameters_and_order_required(self):
        for old,new in ((b'{fixed-common}',b'{wrong}'),(b'-merge -show_warnings',b'-show_warnings'),
                        (b'//  command: read_faults {fixed-common}',b'//  command: read_faults {fixed-translated}')):
            args=list(self.envelope());args[0]=args[0].replace(old,new)
            self.assertFalse(m.evaluate(*args)['passed'])

    def test_tail_marker_and_error_rejected(self):
        for action in ('missing','duplicate','before','error'):
            args=list(self.envelope())
            if action=='missing':args[0]=args[0].replace(args[1],b'')
            if action=='duplicate':args[0]+=args[1]+b'\n'
            if action=='before':args[0]=args[1]+b'\n'+args[0].replace(args[1],b'')
            if action=='error':args[0]+=b'// Error: failed\n'
            self.assertFalse(m.evaluate(*args)['passed'])

    def test_unknown_case_and_changed_design_rejected(self):
        args=list(self.envelope());args[2]='other'
        self.assertFalse(m.evaluate(*args)['passed'])

    def test_invalid_path_variant_rejected(self):
        for line in (b'// Invalid path: unresolved_target\n',
                     b'// Invalid file path: unresolved_target\n',
                     b'// Invalid pin_pathname: unresolved_target\n'):
            args=list(self.envelope());args[0]+=line
            self.assertFalse(m.evaluate(*args)['passed'])

    def test_unseen_single_line_warning_continuation_rejected(self):
        args=list(self.envelope())
        args[0]=args[0].replace(b'Rule FN1 violation occurs 6 times\n',
                               b'Rule FN1 violation occurs 6 times\n//    Previously unseen rule-violation detail\n')
        self.assertFalse(m.evaluate(*args)['passed'])
        args=list(self.envelope());args[0]=args[0].replace(b'read_design fixed',b'read_design other')
        self.assertFalse(m.evaluate(*args)['passed'])

    def test_contract_and_module_registry_agree(self):
        raw=(Path(__file__).resolve().parents[1]/'contracts/direct_tessent_startup_exceptions_e102_v1.json').read_bytes()
        self.assertEqual(json.loads(raw),m.POLICY)

    def test_python36(self):
        ast.parse(Path(m.__file__).read_text(encoding='utf-8'),feature_version=(3,6))


if __name__=='__main__':unittest.main()
