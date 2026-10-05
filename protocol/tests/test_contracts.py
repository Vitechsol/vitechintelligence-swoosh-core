import copy
import json
import hashlib
import struct
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator
from swoosh_contracts import ContractError, SCHEMA, decode

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = {path.stem:json.loads(path.read_text()) for path in (ROOT/"fixtures/v1").glob("*.json")}
encode = lambda value: json.dumps(value).encode()

class ContractsTests(unittest.TestCase):
    def test_schema_and_all_nine_contract_fixtures(self):
        Draft202012Validator.check_schema(SCHEMA)
        self.assertEqual(set(FIXTURES),set(SCHEMA["$defs"]))
        for name, fixture in FIXTURES.items():
            with self.subTest(name=name):self.assertEqual(decode(name,encode(fixture)),fixture)
    def test_unknown_versions_and_extra_authority_fields_are_rejected(self):
        for name, fixture in FIXTURES.items():
            for field,value in (("version","2.0"),("allowed",True),("metadata",{"privateReasoning":"secret"})):
                forged={**fixture,field:value}
                with self.subTest(name=name,field=field),self.assertRaises(ContractError):decode(name,encode(forged))
    def test_missing_commit_proof_or_premature_commit_reference(self):
        value=copy.deepcopy(FIXTURES["ResultEvidence"]);del value["commitRef"]
        with self.assertRaises(ContractError):decode("ResultEvidence",encode(value))
        value["state"]="PRODUCED";value["commitRef"]="claimed-commit"
        with self.assertRaises(ContractError):decode("ResultEvidence",encode(value))
    def test_nonfinite_duplicate_and_oversized_documents(self):
        for value in (b'{"kind":"packet","kind":"action_intent"}',b'{"ttl":NaN}',b' '*65_537):
            with self.assertRaises(ContractError):decode("Packet",value)
    def test_invalid_date_and_unbounded_portable_lease(self):
        for expiry in ("2026-02-30T10:05:00Z","2026-10-05T12:00:00Z",FIXTURES["CapabilityDescriptor"]["issuedAt"]):
            value={**FIXTURES["CapabilityDescriptor"],"expiresAt":expiry}
            with self.assertRaises(ContractError):decode("CapabilityDescriptor",encode(value))
    def test_monotonic_ticks_are_not_portable_authority(self):
        value={**FIXTURES["CapabilityDescriptor"],"expiresTick":8120300}
        with self.assertRaises(ContractError):decode("CapabilityDescriptor",encode(value))
    def test_packet_cross_scope_binding(self):
        for field,value in (("contextId","00000000-0000-4000-8000-000000000999"),("resource","other-site"),("generation",2)):
            packet=copy.deepcopy(FIXTURES["Packet"]);packet["intent"][field]=value
            with self.subTest(field=field),self.assertRaises(ContractError):decode("Packet",encode(packet))
    def test_retry_budget_and_integer_fences(self):
        for field,value in (("attempt",11),("generation",1.5),("maxAttempts",0)):
            document={**FIXTURES["TaskExecution"],field:value}
            with self.assertRaises(ContractError):decode("TaskExecution",encode(document))
    def test_audit_rejects_content_secrets_and_unknown_events(self):
        for field,value in (("prompt","private"),("secret","hidden"),("eventType","model_thought")):
            document={**FIXTURES["AuditEvent"],field:value}
            with self.assertRaises(ContractError):decode("AuditEvent",encode(document))
    def test_capsule_contract_exposes_no_method_content(self):
        value={**FIXTURES["CapsuleExecution"],"protectedMethodology":"private"}
        with self.assertRaises(ContractError):decode("CapsuleExecution",encode(value))
    def test_native_v2_signing_vector_has_independent_length_and_endian_encoding(self):
        vector=json.loads((ROOT/"fixtures/native-v2/signing-vector.json").read_text());binding=vector["binding"]
        raw=b"SWOOSH\x00action-binding\x00v2\x00"+struct.pack(">H",2)+bytes.fromhex(vector["signedClaimV1Fingerprint"])
        for key in ("workflowId","taskId","purpose","destination"):
            value=binding[key].encode();raw+=struct.pack(">I",len(value))+value
        raw+=struct.pack(">Q",binding["generation"])+bytes.fromhex(binding["effectDigest"][7:])+struct.pack(">Q",binding["policyVersion"])+struct.pack(">Q",binding["trustEpoch"])
        self.assertEqual(raw.hex(),vector["signingBytesHex"])
        self.assertEqual("sha256:"+hashlib.sha256(raw).hexdigest(),vector["actionDigest"])

if __name__=="__main__":unittest.main()
