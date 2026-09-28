import copy
import csv
import hashlib
import json
import pathlib
import tempfile
import unittest
import os
import sys

from src.data import build_runtime_training_package_v1 as builder
from src.data import validate_runtime_training_package_v1 as validator
from src.data.runtime_schema import MANIFEST_V2_FIELDS

REPLAY = pathlib.Path(__file__).resolve().parents[1] / "src" / "replay"
if str(REPLAY) not in sys.path:
    sys.path.insert(0, str(REPLAY))
from runtime_accounting_v1 import run_cli

METHODS = ("fixed_heuristic", "d95_safe_then_predicted_cycles", "d95_safe_cost_aware_topk")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuntimeTrainingPackageV1Tests(unittest.TestCase):
    def make_package(self, root, circuit="s13207", family="iscas89_s13207", role="TRAIN"):
        root = pathlib.Path(root)
        graph = root / "graphs" / (circuit + ".json")
        graph.parent.mkdir()
        graph.write_text(json.dumps({
            "schema_version":"runtime-graph-v1", "circuit":circuit,
            "nodes":[{"node_type":"gate","cell_type":"AND2","sequential_flag":0}],
            "edge_index":[],
        }, sort_keys=True), encoding="utf-8")
        actions = [
            {"role":role,"family":family,"circuit":circuit,"action_uid":"a2","action_scheme":"HF","h_limit":"64","m_limit":"0","common_fault_count":"10","execution_status":"SUCCESS","is_d95_feasible":"true","total_cycles":"110","graph_key":"g1"},
            {"role":role,"family":family,"circuit":circuit,"action_uid":"a1","action_scheme":"HMF","h_limit":"64","m_limit":"16","common_fault_count":"10","execution_status":"SUCCESS","is_d95_feasible":"true","total_cycles":"100","graph_key":"g1"},
        ]
        edges = [
            {"action_uid":"a1","invocation_order":"1","mode":"H","retry_group_id":"r1","attempt_id":"t1","prefix_key":""},
            {"action_uid":"a1","invocation_order":"2","mode":"M","retry_group_id":"r2","attempt_id":"t2","prefix_key":""},
            {"action_uid":"a1","invocation_order":"3","mode":"F","retry_group_id":"r4","attempt_id":"t4","prefix_key":""},
            {"action_uid":"a2","invocation_order":"1","mode":"H","retry_group_id":"r3","attempt_id":"t3","prefix_key":""},
            {"action_uid":"a2","invocation_order":"2","mode":"F","retry_group_id":"r5","attempt_id":"t5","prefix_key":""},
        ]
        attempts = []
        for ident, group, wall, timeout, mode in (("t1","r1","2.5","NO_TIMEOUT","H"),("t2","r2","3.5","NO_TIMEOUT","M"),("t3","r3","4.0","NO_TIMEOUT","H"),("t4","r4","1.0","NO_TIMEOUT","F"),("t5","r5","1.0","NO_TIMEOUT","F")):
            row = dict.fromkeys(MANIFEST_V2_FIELDS, "x")
            row.update({"attempt_id":ident,"circuit":circuit,"family":family,"role":role,"mode":mode,"wall_s":wall,"timeout_status":timeout,"retry_order":"1","retry_order_status":"KNOWN_ORDER","retry_group_id":group,"attempt_outcome_class":"SUCCESS"})
            attempts.append(row)
        graphs = [{"graph_key":"g1","circuit":circuit,"graph_path":"graphs/" + circuit + ".json","graph_sha256":digest(graph)}]
        def put(name, fields, rows):
            with (root / name).open("w", encoding="utf-8", newline="") as out:
                writer = csv.DictWriter(out, fieldnames=fields, delimiter="\t", lineterminator="\n")
                writer.writeheader(); writer.writerows(rows)
        put("actions.tsv", validator.ACTION_FIELDS, actions)
        put("action_attempt_edges.tsv", validator.EDGE_FIELDS, edges)
        put("attempts.tsv", MANIFEST_V2_FIELDS, attempts)
        put("graph_manifest.tsv", validator.GRAPH_FIELDS, graphs)
        source_inventory = [
            {field: row[field] for field in validator.SOURCE_INVENTORY_FIELDS}
            for row in attempts
        ]
        put("source_attempt_inventory.tsv", validator.SOURCE_INVENTORY_FIELDS, source_inventory)
        review = {
            "schema_version":"runtime-retry-completeness-review-v1",
            "status":"PASS",
            "reviewer_role":"independent_read_only_reviewer",
            "review_scope":"SOURCE_INVENTORY_TO_PACKAGED_ATTEMPTS",
            "source_inventory_path":"source_attempt_inventory.tsv",
            "source_inventory_sha256":digest(root / "source_attempt_inventory.tsv"),
            "attempts_path":"attempts.tsv",
            "attempts_sha256":digest(root / "attempts.tsv"),
            "circuits":{circuit:len(attempts)},
        }
        (root / "retry_completeness_review.json").write_text(json.dumps(review, sort_keys=True), encoding="utf-8")
        evidence = {
            "schema_version":"runtime-retry-completeness-evidence-v1",
            "status":"PASS_NO_OMITTED_FAILURE_OR_RETRY",
            "circuits":{circuit:{
                "source_inventory_path":"source_attempt_inventory.tsv",
                "source_inventory_sha256":digest(root / "source_attempt_inventory.tsv"),
                "independent_review_receipt_path":"retry_completeness_review.json",
                "independent_review_receipt_sha256":digest(root / "retry_completeness_review.json"),
                "source_attempt_count":len(attempts),
                "packaged_attempt_count":len(attempts),
                "omitted_failure_count":0,
                "omitted_retry_count":0,
                "retry_order_known":True,
            }},
            "independent_review":"PASS",
        }
        (root / "retry_completeness_evidence.json").write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        repo = pathlib.Path(__file__).resolve().parents[1]
        authority = {
            "runtime_training_contract_sha256": digest(repo / "contracts/runtime_training_v1.json"),
            "feature_schema_sha256": digest(repo / "contracts/runtime_feature_schema_v1.json"),
            "split_contract_sha256": digest(repo / "contracts/data_split_v1.json"),
            "runtime_policy_sha256": digest(repo / "contracts/runtime_policy_v1.json"),
        }
        proof = {"status":"PASS_NO_OMITTED_FAILURE_OR_RETRY", "evidence_path":"retry_completeness_evidence.json", "evidence_sha256":digest(root / "retry_completeness_evidence.json"), "circuits":[circuit]}
        manifest = {"schema_version":"runtime-training-source-package-v1", "files":{}, "authority":authority, "success_only_retry_completeness_proof":proof, "prefix_reuse_effective":False}
        for name in validator.REQUIRED_FILES:
            manifest["files"][name] = digest(root / name)
        (root / "package_manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        return actions, edges, attempts, manifest

    def test_pass_builds_normalized_data_without_attempt_or_source_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir()
            self.make_package(source)
            output = pathlib.Path(directory) / "out"
            manifest = builder.build(str(source), str(output))
            self.assertEqual("PASS", manifest["status"])
            self.assertEqual(100.0, manifest["circuit_oracles"]["s13207"])
            self.assertEqual(digest(source / "package_manifest.json"), manifest["input_manifest_sha256"])
            with (output / "features.tsv").open(encoding="utf-8", newline="") as stream:
                features = list(csv.DictReader(stream, delimiter="\t"))
            with (output / "outcomes.tsv").open(encoding="utf-8", newline="") as stream:
                outcomes = list(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(["a1", "a2"], [row["action_uid"] for row in features])
            self.assertEqual("7.000000000", outcomes[0]["policy_charged_runtime_s"])
            self.assertEqual("1", outcomes[0]["epsilon_hit"])
            self.assertNotIn("attempt_id", features[0])
            self.assertNotIn("total_cycles", features[0])
            self.assertEqual(manifest, validator.validate_output_package(str(output)))

    def test_failed_and_timeout_actions_are_retained_and_charged(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir()
            actions, edges, attempts, manifest = self.make_package(source)
            actions[0].update(execution_status="TIMEOUT", is_d95_feasible="false", total_cycles="NA")
            attempts[4].update(wall_s="", timeout_status="TIMEOUT", attempt_outcome_class="TIMEOUT")
            self.write_all(source, actions, edges, attempts, manifest)
            result = validator.validate_source_package(str(source))
            self.assertEqual(34.0, result["derived"]["a2"]["policy_charged_runtime_s"])
            self.assertFalse(result["derived"]["a2"]["epsilon_hit"])

    def test_authority_and_completeness_scope_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir()
            _, _, _, manifest = self.make_package(source)
            manifest["authority"]["runtime_policy_sha256"] = "f" * 64
            self.write_manifest(source, manifest)
            with self.assertRaisesRegex(ValueError, "PACKAGE_AUTHORITY_MISMATCH"):
                validator.validate_source_package(str(source))

    def test_graph_payload_and_completeness_evidence_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir()
            _, _, _, manifest = self.make_package(source)
            graph = source / "graphs" / "s13207.json"
            payload = json.loads(graph.read_text(encoding="utf-8"))
            payload["nodes"][0]["wall_s"] = 9.0
            graph.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            graphs = [{"graph_key":"g1","circuit":"s13207","graph_path":"graphs/s13207.json","graph_sha256":digest(graph)}]
            self.write_tsv(source / "graph_manifest.tsv", validator.GRAPH_FIELDS, graphs)
            manifest["files"]["graph_manifest.tsv"] = digest(source / "graph_manifest.tsv")
            self.write_manifest(source, manifest)
            with self.assertRaisesRegex(ValueError, "GRAPH_FEATURE_NOT_ALLOWLISTED"):
                validator.validate_source_package(str(source))
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir()
            _, _, _, manifest = self.make_package(source)
            manifest["success_only_retry_completeness_proof"]["evidence_sha256"] = "f" * 64
            self.write_manifest(source, manifest)
            with self.assertRaisesRegex(ValueError, "EVIDENCE_MISMATCH"):
                validator.validate_source_package(str(source))

    def test_max_one_retry_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir()
            actions, edges, attempts, manifest = self.make_package(source)
            attempts[0]["attempt_outcome_class"] = "FAILURE"
            for suffix, order, outcome in (("6", "2", "FAILURE"), ("7", "3", "SUCCESS")):
                row = dict(attempts[0])
                row.update(attempt_id="t" + suffix, retry_order=order, attempt_outcome_class=outcome)
                attempts.append(row)
            for edge in edges:
                if edge["action_uid"] == "a1" and int(edge["invocation_order"]) > 1:
                    edge["invocation_order"] = str(int(edge["invocation_order"]) + 2)
            edges.extend([
                {"action_uid":"a1","invocation_order":"2","mode":"H","retry_group_id":"r1","attempt_id":"t6","prefix_key":""},
                {"action_uid":"a1","invocation_order":"3","mode":"H","retry_group_id":"r1","attempt_id":"t7","prefix_key":""},
            ])
            evidence_path = source / "retry_completeness_evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["circuits"]["s13207"]["source_attempt_count"] = len(attempts)
            evidence["circuits"]["s13207"]["packaged_attempt_count"] = len(attempts)
            evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
            manifest["success_only_retry_completeness_proof"]["evidence_sha256"] = digest(evidence_path)
            self.write_all(source, actions, edges, attempts, manifest)
            with self.assertRaisesRegex(ValueError, "MAX_RETRY_EXCEEDED"):
                validator.validate_source_package(str(source))

    def test_source_inventory_and_independent_review_are_byte_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir()
            _, _, _, manifest = self.make_package(source)
            inventory = source / "source_attempt_inventory.tsv"
            inventory.write_text(inventory.read_text(encoding="utf-8").replace("SUCCESS", "FAILURE", 1), encoding="utf-8")
            manifest["files"]["source_attempt_inventory.tsv"] = digest(inventory)
            self.write_manifest(source, manifest)
            with self.assertRaisesRegex(ValueError, "SOURCE_ATTEMPT_INVENTORY_VALUE_MISMATCH|EVIDENCE_SCHEMA"):
                validator.validate_source_package(str(source))
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir()
            _, _, _, manifest = self.make_package(source)
            review = source / "retry_completeness_review.json"
            payload = json.loads(review.read_text(encoding="utf-8"))
            payload["attempts_sha256"] = "0" * 64
            review.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            evidence = source / "retry_completeness_evidence.json"
            evidence_payload = json.loads(evidence.read_text(encoding="utf-8"))
            evidence_payload["circuits"]["s13207"]["independent_review_receipt_sha256"] = digest(review)
            evidence.write_text(json.dumps(evidence_payload, sort_keys=True), encoding="utf-8")
            manifest["files"]["retry_completeness_review.json"] = digest(review)
            manifest["files"]["retry_completeness_evidence.json"] = digest(evidence)
            manifest["success_only_retry_completeness_proof"]["evidence_sha256"] = digest(evidence)
            self.write_manifest(source, manifest)
            with self.assertRaisesRegex(ValueError, "COMPLETENESS_REVIEW_BINDING"):
                validator.validate_source_package(str(source))

    def test_replay_cli_requires_validation_package_and_freeze_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source"; source.mkdir()
            self.make_package(source, circuit="s5378", family="iscas89_s5378", role="VALIDATION")
            package = root / "package"
            builder.build(str(source), str(package))
            ranking = root / "ranking.tsv"
            rank_rows = []
            for method in METHODS:
                rank_rows.extend([
                    {"method":method,"circuit":"s5378","rank":"1","action_uid":"a1"},
                    {"method":method,"circuit":"s5378","rank":"2","action_uid":"a2"},
                ])
            self.write_tsv(ranking, ("method","circuit","rank","action_uid"), rank_rows)
            repo = pathlib.Path(__file__).resolve().parents[1]
            freeze = root / "freeze.json"
            generator = root / "ranking_generator.py"
            generator.write_text("# deterministic ranking fixture\n", encoding="utf-8")
            preoutcome = root / "preoutcome_receipt.json"
            preoutcome_payload = {
                "schema_version":"runtime-ranking-preoutcome-receipt-v1",
                "status":"PASS_FROZEN_WITHOUT_OUTCOMES",
                "features_sha256":digest(package / "features.tsv"),
                "ranking_sha256":digest(ranking),
                "ranking_generator_path":"ranking_generator.py",
                "ranking_generator_sha256":digest(generator),
                "outcome_artifacts_present":False,
                "events":["FEATURES_OPENED", "RANKING_WRITTEN", "RECEIPT_SEALED"],
            }
            preoutcome.write_text(json.dumps(preoutcome_payload, sort_keys=True), encoding="utf-8")
            freeze_payload = {
                "schema_version":"runtime-ranking-freeze-v1",
                "status":"FROZEN_BEFORE_OUTCOME_ACCESS",
                "features_sha256":digest(package / "features.tsv"),
                "ranking_sha256":digest(ranking),
                "training_contract_sha256":digest(repo / "contracts/runtime_training_v1.json"),
                "split_contract_sha256":digest(repo / "contracts/data_split_v1.json"),
                "ranking_generator_path":"ranking_generator.py",
                "ranking_generator_sha256":digest(generator),
                "preoutcome_receipt_path":"preoutcome_receipt.json",
                "preoutcome_receipt_sha256":digest(preoutcome),
                "methods":list(METHODS),
                "ranking_frozen_before_outcome_access":True,
                "outcome_files_opened":False,
            }
            freeze.write_text(json.dumps(freeze_payload, sort_keys=True), encoding="utf-8")
            output = root / "replay.json"
            ledger = root / "outcome_access.jsonl"
            run_cli(package, ranking, freeze, ledger, output, METHODS)
            self.assertEqual("PASS_VALIDATION_REPLAY", json.loads(output.read_text(encoding="utf-8"))["status"])
            ledger_rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(["PREOUTCOME_RECEIPT_VERIFIED", "OUTCOMES_OPENED_AFTER_FREEZE"], [row["event"] for row in ledger_rows])
            self.assertEqual(ledger_rows[0]["event_sha256"], ledger_rows[1]["previous_event_sha256"])
            freeze_payload["outcome_files_opened"] = True
            freeze.write_text(json.dumps(freeze_payload, sort_keys=True), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "binding mismatch"):
                run_cli(package, ranking, freeze, root / "access2.jsonl", root / "replay2.json", METHODS)

            freeze_payload["outcome_files_opened"] = False
            freeze_payload["ranking_generator_sha256"] = "2" * 64
            freeze.write_text(json.dumps(freeze_payload, sort_keys=True), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "binding mismatch"):
                run_cli(package, ranking, freeze, root / "access3.jsonl", root / "replay3.json", METHODS)
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir()
            _, _, _, manifest = self.make_package(source)
            manifest["success_only_retry_completeness_proof"]["circuits"] = ["s5378"]
            self.write_manifest(source, manifest)
            with self.assertRaisesRegex(ValueError, "SUCCESS_ONLY_COMPLETENESS_SCOPE_MISMATCH"):
                validator.validate_source_package(str(source))

    def test_forbidden_role_and_symlink_graph_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir(); actions, _, _, manifest = self.make_package(source)
            actions[0]["role"] = "PILOT"
            self.write_actions_and_manifest(source, actions, manifest)
            with self.assertRaisesRegex(ValueError, "ROLE_OR_FAMILY_FORBIDDEN"):
                validator.validate_source_package(str(source))
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source"; source.mkdir(); _, _, _, manifest = self.make_package(source)
            graph = source / "graphs" / "s13207.json"
            link = source / "graphs" / "link.json"
            try:
                link.symlink_to(graph)
            except OSError as exc:
                self.skipTest("symlink creation is unavailable: %s" % exc)
            graphs = [{"graph_key":"g1","circuit":"s13207","graph_path":"graphs/link.json","graph_sha256":digest(graph)}]
            self.write_tsv(source / "graph_manifest.tsv", validator.GRAPH_FIELDS, graphs)
            manifest["files"]["graph_manifest.tsv"] = digest(source / "graph_manifest.tsv")
            self.write_manifest(source, manifest)
            with self.assertRaisesRegex(ValueError, "PACKAGE_PATH_INVALID"):
                validator.validate_source_package(str(source))

    def test_replay_rejects_feature_and_freeze_artifact_symlinks_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            package = root / "package"; package.mkdir()
            outside = root / "outside.tsv"; outside.write_text("sensitive\n", encoding="utf-8")
            try:
                (package / "features.tsv").symlink_to(outside)
            except OSError as exc:
                self.skipTest("symlink creation is unavailable: %s" % exc)
            with self.assertRaisesRegex(ValueError, "PACKAGE_PATH_INVALID|non-symlink"):
                run_cli(package, root / "ranking.tsv", root / "freeze.json", root / "access.jsonl", root / "out.json", METHODS)

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            target = root / "target.py"; target.write_text("# generator\n", encoding="utf-8")
            link = root / "generator.py"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest("symlink creation is unavailable: %s" % exc)
            freeze = root / "freeze.json"; freeze.write_text("{}", encoding="utf-8")
            from runtime_accounting_v1 import _artifact_beside
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                _artifact_beside(freeze, "generator.py")

    def test_replay_rejects_package_root_and_ranking_symlinks_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            real_package = root / "real_package"; real_package.mkdir()
            package_link = root / "package_link"
            try:
                package_link.symlink_to(real_package, target_is_directory=True)
            except OSError as exc:
                self.skipTest("symlink creation is unavailable: %s" % exc)
            with self.assertRaisesRegex(ValueError, "package root path or parent must not be a symlink"):
                run_cli(package_link, root / "ranking.tsv", root / "freeze.json", root / "access.jsonl", root / "out.json", METHODS)

            real_ranking = root / "real_ranking.tsv"; real_ranking.write_text("sensitive\n", encoding="utf-8")
            ranking_link = root / "ranking.tsv"; ranking_link.symlink_to(real_ranking)
            with self.assertRaisesRegex(ValueError, "ranking path or parent must not be a symlink"):
                run_cli(real_package, ranking_link, root / "freeze.json", root / "access2.jsonl", root / "out2.json", METHODS)

    def test_runtime_failures_retries_prefix_and_completeness_fail(self):
        mutations = (
            ("UNKNOWN_RETRY_ORDER", lambda a,e,t,m: t.__setitem__(0, dict(t[0], retry_order_status="UNKNOWN_ORDER"))),
            ("TIMEOUT_RETRY_FORBIDDEN", self.timeout_retry),
            ("PREFIX_REUSE_NOT_DISABLED", lambda a,e,t,m: e.__setitem__(0, dict(e[0], prefix_key="p"))),
            ("SUCCESS_ONLY_COMPLETENESS_UNPROVEN", lambda a,e,t,m: m.__setitem__("success_only_retry_completeness_proof", False)),
            ("MISSING_WALL_TIME", lambda a,e,t,m: t.__setitem__(0, dict(t[0], wall_s=""))),
        )
        for expected, mutate in mutations:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                source = pathlib.Path(directory) / "source"; source.mkdir(); a,e,t,m = self.make_package(source)
                mutate(a,e,t,m); self.write_all(source,a,e,t,m)
                with self.assertRaisesRegex(ValueError, expected): validator.validate_source_package(str(source))

    @staticmethod
    def timeout_retry(a, edges, attempts, manifest):
        attempts[0]["timeout_status"] = "TIMEOUT"
        attempts[0]["attempt_outcome_class"] = "TIMEOUT"
        attempts[1]["retry_group_id"] = "r1"; attempts[1]["retry_order"] = "2"; attempts[1]["mode"] = "H"
        edges[1]["retry_group_id"] = "r1"; edges[1]["mode"] = "H"

    @staticmethod
    def write_tsv(path, fields, rows):
        with path.open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=fields, delimiter="\t", lineterminator="\n")
            writer.writeheader(); writer.writerows(rows)

    def write_actions_and_manifest(self, source, actions, manifest):
        self.write_tsv(source / "actions.tsv", validator.ACTION_FIELDS, actions)
        manifest["files"]["actions.tsv"] = digest(source / "actions.tsv")
        self.write_manifest(source, manifest)

    @staticmethod
    def write_manifest(source, manifest):
        (source / "package_manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    def write_all(self, source, actions, edges, attempts, manifest):
        self.write_tsv(source / "actions.tsv", validator.ACTION_FIELDS, actions)
        self.write_tsv(source / "action_attempt_edges.tsv", validator.EDGE_FIELDS, edges)
        self.write_tsv(source / "attempts.tsv", MANIFEST_V2_FIELDS, attempts)
        inventory = [{field: row[field] for field in validator.SOURCE_INVENTORY_FIELDS} for row in attempts]
        self.write_tsv(source / "source_attempt_inventory.tsv", validator.SOURCE_INVENTORY_FIELDS, inventory)
        counts = {}
        for row in attempts: counts[row["circuit"]] = counts.get(row["circuit"], 0) + 1
        review = {
            "schema_version":"runtime-retry-completeness-review-v1", "status":"PASS",
            "reviewer_role":"independent_read_only_reviewer",
            "review_scope":"SOURCE_INVENTORY_TO_PACKAGED_ATTEMPTS",
            "source_inventory_path":"source_attempt_inventory.tsv",
            "source_inventory_sha256":digest(source / "source_attempt_inventory.tsv"),
            "attempts_path":"attempts.tsv", "attempts_sha256":digest(source / "attempts.tsv"),
            "circuits":dict(sorted(counts.items())),
        }
        (source / "retry_completeness_review.json").write_text(json.dumps(review, sort_keys=True), encoding="utf-8")
        evidence_path = source / "retry_completeness_evidence.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        for circuit, count in counts.items():
            if circuit in evidence["circuits"]:
                evidence["circuits"][circuit].update(
                    source_inventory_sha256=digest(source / "source_attempt_inventory.tsv"),
                    independent_review_receipt_sha256=digest(source / "retry_completeness_review.json"),
                    source_attempt_count=count, packaged_attempt_count=count,
                )
        evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
        if isinstance(manifest.get("success_only_retry_completeness_proof"), dict):
            manifest["success_only_retry_completeness_proof"]["evidence_sha256"] = digest(evidence_path)
        for name in validator.REQUIRED_FILES: manifest["files"][name] = digest(source / name)
        self.write_manifest(source, manifest)


if __name__ == "__main__":
    unittest.main()
