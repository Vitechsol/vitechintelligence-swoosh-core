import copy
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location("rights",Path(__file__).resolve().parents[1]/"check-contributor-rights.py")
rights=importlib.util.module_from_spec(spec);spec.loader.exec_module(rights)

class RightsTests(unittest.TestCase):
    def setUp(self):
        self.policy={"schemaVersion":1,"maintainerAccounts":["owner"],"cla":{"status":"draft","agreementDigest":None},"acceptances":[]}
    def test_maintainer_origin_is_separate_from_a_cla_signature(self):
        self.assertTrue(rights.evaluate(self.policy,"owner",["owner"])[0])
        self.assertEqual(self.policy['acceptances'],[])
    def test_external_pr_cannot_use_draft_terms(self):
        self.assertFalse(rights.evaluate(self.policy,"external",["external"])[0])
    def test_maintainer_pr_does_not_cover_external_authors(self):
        self.assertFalse(rights.evaluate(self.policy,"owner",["external"])[0])
    def test_missing_authors_and_empty_history_fail_closed(self):
        self.assertFalse(rights.evaluate(self.policy,"owner",[])[0])
        self.assertFalse(rights.evaluate(self.policy,"owner",[""])[0])
    def test_bots_have_no_automatic_exemption(self):
        self.assertFalse(rights.evaluate(self.policy,"owner",["bot[bot]"])[0])
    def test_current_verified_acceptance_is_required(self):
        policy=copy.deepcopy(self.policy);policy['cla']={"status":"active","agreementDigest":"a"*64}
        policy['acceptances']=[{"account":"external","agreementDigest":"a"*64,"verified":True,"acceptanceRecordDigest":"b"*64}]
        self.assertTrue(rights.evaluate(policy,"external",["external"])[0])
        policy['acceptances'][0]['verified']=False
        self.assertFalse(rights.evaluate(policy,"external",["external"])[0])
    def test_changed_agreement_does_not_reuse_old_signature(self):
        policy=copy.deepcopy(self.policy);policy['cla']={"status":"active","agreementDigest":"a"*64}
        policy['acceptances']=[{"account":"external","agreementDigest":"c"*64,"verified":True,"acceptanceRecordDigest":"b"*64}]
        self.assertFalse(rights.evaluate(policy,"external",["external"])[0])
    def test_no_record_digest_or_invalid_policy_denies(self):
        self.assertFalse(rights.evaluate({},"owner",["owner"])[0])
        policy=copy.deepcopy(self.policy);policy['cla']={"status":"active","agreementDigest":"a"*64}
        policy['acceptances']=[{"account":"external","agreementDigest":"a"*64,"verified":True}]
        self.assertFalse(rights.evaluate(policy,"external",["external"])[0])
if __name__=="__main__":unittest.main()
