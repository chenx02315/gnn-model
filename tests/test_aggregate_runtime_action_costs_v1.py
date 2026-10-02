from __future__ import print_function

import csv
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "data"))
import aggregate_runtime_action_costs_v1 as aggregate
from audit_runtime_action_attempt_mapping_v1 import ACTION_FIELDS, EDGE_FIELDS
from runtime_schema import MANIFEST_V2_FIELDS


class AggregationTests(unittest.TestCase):
    def write_tsv(self, path, fields, rows):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer=csv.DictWriter(stream,fieldnames=fields,delimiter="\t",lineterminator="\n")
            writer.writeheader(); writer.writerows(rows)

    def sha(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_mean_keeps_failed_and_retry_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            sources=("c:hf_coarse:H64-F4:1","c:hf_refine:H64-F4:1")
            action={"action_uid":"c:HF:h4","circuit":"c","action_scheme":"HF","mode_stack":"H64-F4",
                    "h_patterns":"4","m_patterns":"","repeat_measurement_count":"2",
                    "source_candidate_uids":"|".join(sources),"source_stages":"hf_coarse|hf_refine",
                    "outcome_conflict":"false","outcome_conflict_fields":""}
            self.write_tsv(root/"actions.tsv",ACTION_FIELDS,[action])
            base=dict((field,"") for field in MANIFEST_V2_FIELDS)
            manifest=[]
            for attempt_id,wall,outcome in (("a1","2.0","SUCCESS"),("a2","4.0","FAILURE"),("a3","10.0","SUCCESS")):
                row=dict(base); row.update(attempt_id=attempt_id,circuit="c",wall_s=wall,
                                           attempt_outcome_class=outcome,retry_group_id="g"+attempt_id[-1])
                manifest.append(row)
            manifest_path=root/"manifests"/"c_attempt_manifest_v2_remediated.tsv"
            self.write_tsv(manifest_path,MANIFEST_V2_FIELDS,manifest)
            edges=[]
            for source,ids in ((sources[0],("a1","a2")),(sources[1],("a3",))):
                for attempt_id in ids:
                    edges.append({"action_uid":"c:HF:h4","source_candidate_uid":source,"circuit":"c",
                                  "stage":"02_hf_coarse","action_scheme":"HF","h_patterns":"4","m_patterns":"",
                                  "mode":"F","retry_group_id":"g","retry_order":"1","attempt_id":attempt_id,
                                  "mapping_rule":"F_SEARCH_RUN_ID"})
            edge_path=root/"edges.tsv"; self.write_tsv(edge_path,EDGE_FIELDS,edges)
            receipt={"status":"PASS_MAPPING_REPEAT_AGGREGATION_PENDING",
                     "candidate_space_sha256":self.sha(root/"actions.tsv"),
                     "manifest_sha256":{"c":self.sha(manifest_path)},
                     "output_sha256":{"invocation_attempt_edges_v1.tsv":self.sha(edge_path)}}
            receipt_path=root/"mapping.json"; receipt_path.write_text(json.dumps(receipt),encoding="utf-8")
            self.assertEqual(0,aggregate.aggregate(str(root/"actions.tsv"),str(edge_path),str(receipt_path),
                                                   str(root/"manifests"),str(root/"out")))
            with (root/"out"/"action_runtime_costs_v1.tsv").open(encoding="utf-8") as stream:
                row=next(csv.DictReader(stream,delimiter="\t"))
            self.assertEqual("8.000000000",row["wall_time_mean_s"])
            self.assertEqual("1",row["failed_session_count"])
            self.assertEqual("3",row["attempt_session_count"])
            self.assertEqual("ARITHMETIC_MEAN_ALL_INVOCATIONS",row["aggregation_policy"])


if __name__ == "__main__":
    unittest.main()
