"""Fault-oriented release gate tests; all HTTP writes are isolated test doubles."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.error
from urllib.parse import urlsplit

SCRIPT=Path(__file__).resolve().parents[1]/"publish-verified-preview.py"
spec=importlib.util.spec_from_file_location("publisher",SCRIPT)
publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)

class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.head="a"*40;self.reviewed="b"*40;self.posts=[];self.tag=None;self.release=None
        policy=json.loads((SCRIPT.parents[1]/'.github/release-policy.json').read_text())
        self.repo={"private":False,"default_branch":"main"}
        self.branch={"protected":True,"commit":{"sha":self.head}}
        self.pull={"merged":True,"base":{"ref":"main"},"merge_commit_sha":self.head,"head":{"sha":self.reviewed},"user":{"login":"owner"}}
        self.reviews=[{"user":{"type":"User","login":"independent"},"state":"APPROVED","commit_id":self.reviewed,"html_url":"https://github.com/review"}]
        self.runs=[];self.jobs={}
        for number,name in enumerate(policy['requiredWorkflows'],1):
            self.runs.append({"id":number,"name":name,"head_sha":self.head,"head_branch":"main","status":"completed","conclusion":"success","html_url":"https://github.com/run/"+str(number)})
            jobs=[{"name":item['name'],"conclusion":"success","steps":[{"name":step,"conclusion":"success"} for step in item['steps']]} for item in policy['requiredJobs'][name]]
            self.jobs[str(number)]={"total_count":len(jobs),"jobs":jobs}

    def http(self,request,timeout):
        path=urlsplit(request.full_url).path.removeprefix('/repos/example/core')
        if request.get_method()=='POST':
            value=json.loads(request.data);self.posts.append((path,value))
            if path=='/git/refs':self.tag={"object":{"type":"commit","sha":value['sha']}};data=self.tag
            elif path=='/releases':self.release={**value,"html_url":"https://github.com/example/core/releases/tag/v0.1.0-preview"};data=self.release
            else:raise AssertionError(path)
        elif path=='':data=self.repo
        elif path=='/branches/main':data=self.branch
        elif path=='/pulls/13':data=self.pull
        elif path=='/pulls/13/reviews':data=self.reviews
        elif path=='/actions/runs':data={"workflow_runs":self.runs}
        elif path.startswith('/actions/runs/') and path.endswith('/jobs'):data=self.jobs[path.split('/')[3]]
        elif path.startswith('/git/ref/tags/'):
            if self.tag is None:raise urllib.error.HTTPError(request.full_url,404,'missing',{},None)
            data=self.tag
        elif path.startswith('/releases/tags/'):
            if self.release is None:raise urllib.error.HTTPError(request.full_url,404,'missing',{},None)
            data=self.release
        else:raise AssertionError(path)
        return io.BytesIO(json.dumps(data).encode())

    def run_publish(self):
        with patch.object(sys,'argv',[str(SCRIPT),'--reviewed-pr','13']),patch.dict('os.environ',{'PREVIEW_REPOSITORY':'example/core','PREVIEW_GITHUB_TOKEN':'synthetic-test-token'}),patch.object(publisher.subprocess,'check_output',return_value=self.head),patch.object(publisher.urllib.request,'urlopen',side_effect=self.http),patch('sys.stdout',io.StringIO()):
            publisher.main()

    def blocked(self):
        with self.assertRaises(SystemExit):self.run_publish()
        self.assertEqual(self.posts,[])

    def test_positive_control_publishes_immutable_preview(self):
        self.run_publish()
        self.assertEqual(self.tag['object']['sha'],self.head)
        self.assertTrue(self.release['prerelease'])
        self.assertEqual(self.release['target_commitish'],self.head)

    def test_private_or_unprotected_repo_cannot_publish(self):
        self.repo['private']=True;self.blocked()
        self.repo['private']=False;self.branch['protected']=False;self.blocked()

    def test_stale_review_bot_and_author_approval_cannot_publish(self):
        original=copy.deepcopy(self.reviews)
        for field,value in (('commit_id','c'*40),('state','DISMISSED')):
            self.reviews=copy.deepcopy(original);self.reviews[0][field]=value;self.blocked()
        self.reviews=copy.deepcopy(original);self.reviews[0]['user']['type']='Bot';self.blocked()
        self.reviews=copy.deepcopy(original);self.reviews[0]['user']['login']='owner';self.blocked()

    def test_green_workflow_with_skipped_required_step_cannot_publish(self):
        self.jobs['1']['jobs'][0]['steps'][0]['conclusion']='skipped';self.blocked()

    def test_missing_failed_or_wrong_sha_run_cannot_publish(self):
        original=copy.deepcopy(self.runs)
        self.runs=[];self.blocked()
        self.runs=copy.deepcopy(original);self.runs[0]['conclusion']='failure';self.blocked()
        self.runs=copy.deepcopy(original);self.runs[0]['head_sha']='c'*40;self.blocked()

    def test_same_sha_tag_recovers_and_complete_release_is_idempotent(self):
        self.tag={'object':{'type':'commit','sha':self.head}}
        self.run_publish();self.assertEqual([p for p,_ in self.posts],['/releases'])
        self.posts.clear();self.run_publish();self.assertEqual(self.posts,[])

    def test_different_sha_tag_is_never_overwritten(self):
        self.tag={'object':{'type':'commit','sha':'c'*40}};self.blocked()

if __name__=='__main__':unittest.main()
