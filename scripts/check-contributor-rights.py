#!/usr/bin/env python3
"""Fail closed on unverified external contributor rights. No PR code is executed.

The trusted base-branch registry is authoritative. A checkbox, PR text, bot flag,
or a signed commit is not a CLA signature. Legal acceptance is recorded by the
maintainer only after external verification against approved terms.
"""
import argparse
import json
import os
from pathlib import Path
import re
import urllib.request


def evaluate(policy: dict, pull_author: str, contributors: list[str]) -> tuple[bool,str]:
    if policy.get("schemaVersion")!=1 or not isinstance(pull_author,str) or not pull_author or not contributors:
        return False,"INVALID_CONTRIBUTOR_EVIDENCE"
    maintainers=policy.get("maintainerAccounts",[])
    if not isinstance(maintainers,list) or not maintainers or not all(isinstance(v,str) and v for v in maintainers):
        return False,"INVALID_RIGHTS_POLICY"
    if not all(isinstance(v,str) and v for v in contributors):
        return False,"UNKNOWN_CONTRIBUTOR"
    accounts=set(contributors+[pull_author])
    if accounts.issubset(set(maintainers)):
        return True,"MAINTAINER_ORIGIN_REQUIRES_PROVENANCE_REVIEW"
    agreement=policy.get("cla",{})
    agreement_digest=agreement.get("agreementDigest")
    if agreement.get("status")!="active" or not isinstance(agreement_digest,str) or not re.fullmatch(r"[0-9a-f]{64}",agreement_digest):
        return False,"EXTERNAL_CONTRIBUTION_BLOCKED_CLA_NOT_ACTIVE"
    accepted=set()
    for item in policy.get("acceptances",[]):
        if isinstance(item,dict) and item.get("agreementDigest")==agreement_digest and item.get("verified") is True and isinstance(item.get("acceptanceRecordDigest"),str) and re.fullmatch(r"[0-9a-f]{64}",item["acceptanceRecordDigest"]) and isinstance(item.get("account"),str) and item["account"]:
            accepted.add(item["account"])
    return (True,"VERIFIED_CURRENT_AGREEMENT_ACCEPTANCE") if accounts.issubset(set(maintainers)|accepted) else (False,"UNVERIFIED_EXTERNAL_CONTRIBUTOR")


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--repository",required=True)
    parser.add_argument("--pull-request-number",type=int,required=True)
    args=parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",args.repository) or args.pull_request_number<1:
        raise SystemExit("invalid repository or PR")
    token=os.environ["CONTRIBUTION_GITHUB_TOKEN"]
    base="https://api.github.com/repos/"+args.repository+"/pulls/"+str(args.pull_request_number)
    def get(url):
        request=urllib.request.Request(url,headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
        with urllib.request.urlopen(request,timeout=20) as response:
            data=response.read(2_000_001)
        if len(data)>2_000_000:raise RuntimeError("GitHub evidence too large")
        return json.loads(data)
    pull=get(base)
    head=pull["head"]["sha"]
    if not isinstance(head,str) or not re.fullmatch(r"[0-9a-f]{40}",head):
        raise SystemExit("invalid immutable PR head")
    status_url="https://api.github.com/repos/"+args.repository+"/statuses/"+head
    def status(state,reason):
        payload=json.dumps({"state":state,"context":"contributor-rights","description":reason[:140]}).encode()
        request=urllib.request.Request(status_url,data=payload,method="POST",headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","Content-Type":"application/json","X-GitHub-Api-Version":"2022-11-28"})
        with urllib.request.urlopen(request,timeout=20) as response:response.read(16384)
    status("pending","Verifying external contributor rights against trusted base")
    # Bound work and avoid silently omitting additional pages/contributors.
    if type(pull.get("commits")) is not int or not 1<=pull["commits"]<=100:
        status("failure","Manual rights review required for commit count")
        raise SystemExit("manual rights review required for commit count")
    commits=get(base+"/commits?per_page=100")
    if not isinstance(commits,list) or len(commits)!=pull["commits"] or commits[-1].get("sha")!=head:
        status("failure","Incomplete contributor evidence")
        raise SystemExit("incomplete contributor evidence")
    contributors=[]
    for commit in commits:
        author=commit.get("author")
        login=author.get("login") if isinstance(author,dict) else None
        # Coauthors may not map to verified accounts. Do not infer their identity
        # from an arbitrary email or treat a maintainer's PR as their signature.
        message=commit.get("commit",{}).get("message","")
        if not login or re.search(r"(?im)^\s*co-authored-by\s*:",message):
            status("failure","Manual rights review required for unknown author/coauthor")
            raise SystemExit("manual rights review required for unknown author/coauthor")
        contributors.append(login)
    policy=json.loads((Path(__file__).resolve().parents[1]/".github/contributor-rights.json").read_text())
    allowed,reason=evaluate(policy,pull.get("user",{}).get("login"),contributors)
    if get(base)["head"]["sha"]!=head:
        status("failure","PR head changed during verification")
        raise SystemExit("PR head changed during verification")
    status("success" if allowed else "failure",reason)
    print(json.dumps({"allowed":allowed,"reason":reason,"headSha":pull["head"]["sha"],"claActive":policy.get("cla",{}).get("status")=="active"}))
    if not allowed:raise SystemExit(1)

if __name__=="__main__":main()
