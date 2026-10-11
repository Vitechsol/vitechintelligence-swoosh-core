#!/usr/bin/env python3
"""Publish only an exact public/protected/main candidate with human review and push CI.

Run exclusively from the trusted main workflow. No deployment, admin changes,
review fabrication, tag replacement, or untrusted PR code is performed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--reviewed-pr",type=int,required=True)
    args=parser.parse_args()
    repository=os.environ["PREVIEW_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",repository) or args.reviewed_pr<1:raise SystemExit("invalid release request")
    token=os.environ["PREVIEW_GITHUB_TOKEN"]
    root=Path(__file__).resolve().parents[1]
    policy=json.loads((root/".github/release-policy.json").read_text())
    if policy.get("schemaVersion")!=1 or policy.get("branch")!="main" or policy.get("tag")!="v0.1.0-preview" or not policy.get("requiredWorkflows"):
        raise SystemExit("unsupported release policy")
    head=subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}",head):raise SystemExit("invalid source SHA")
    base="https://api.github.com/repos/"+repository
    def api(path,data=None):
        payload=None if data is None else json.dumps(data).encode()
        request=urllib.request.Request(base+path,data=payload,headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","Content-Type":"application/json","X-GitHub-Api-Version":"2022-11-28"})
        with urllib.request.urlopen(request,timeout=20) as response:value=response.read(2_000_001)
        if len(value)>2_000_000:raise RuntimeError("release evidence too large")
        return json.loads(value)
    repo=api("");branch=api("/branches/main")
    if repo.get("private") is not False or repo.get("default_branch")!="main" or branch.get("protected") is not True or branch.get("commit",{}).get("sha")!=head:
        raise SystemExit("public, protected, exact main is required before preview publication")
    pull=api("/pulls/"+str(args.reviewed_pr))
    if not pull.get("merged") or pull.get("base",{}).get("ref")!="main" or pull.get("merge_commit_sha")!=head:
        raise SystemExit("candidate must be the resulting main commit of the reviewed PR")
    reviews=api("/pulls/"+str(args.reviewed_pr)+"/reviews?per_page=100")
    if not isinstance(reviews,list) or len(reviews)>=100:raise SystemExit("manual review evidence check required")
    latest={}
    for review in reviews:
        user=review.get("user",{})
        # Comments do not dismiss an approval; actual dismissals/change requests do.
        if user.get("type")=="User" and review.get("state") in {"APPROVED","CHANGES_REQUESTED","DISMISSED"}:
            latest[user.get("login")]=review
    approved=[r for r in latest.values() if r.get("state")=="APPROVED" and r.get("commit_id")==pull["head"]["sha"] and r.get("user",{}).get("login")!=pull["user"]["login"]]
    if not approved:raise SystemExit("recorded independent human approval of the exact PR head is required")
    if any(r.get("state")=="CHANGES_REQUESTED" for r in latest.values()):raise SystemExit("unresolved human change request blocks publication")
    runs=api("/actions/runs?head_sha="+head+"&event=push&per_page=100")
    evidence=[]
    for name in policy["requiredWorkflows"]:
        matching=[r for r in runs.get("workflow_runs",[]) if r.get("name")==name and r.get("head_sha")==head and r.get("head_branch")=="main"]
        if not matching:raise SystemExit("missing post-merge workflow: "+name)
        latest_run=max(matching,key=lambda r:r["id"])
        if latest_run.get("status")!="completed" or latest_run.get("conclusion")!="success":raise SystemExit("latest exact-main workflow is not green: "+name)
        jobs=api("/actions/runs/"+str(latest_run["id"])+"/jobs?per_page=100")
        if jobs.get("total_count",0)!=len(jobs.get("jobs",[])) or not jobs.get("jobs") or any(j.get("conclusion")!="success" for j in jobs["jobs"]):
            raise SystemExit("required workflow jobs incomplete or not successful")
        required=policy.get("requiredJobs",{}).get(name)
        if not isinstance(required,list) or not required:raise SystemExit("missing workflow step policy")
        for item in required:
            matches=[j for j in jobs["jobs"] if j.get("name")==item["name"]]
            if len(matches)!=1:raise SystemExit("required job missing: "+item["name"])
            for step_name in item["steps"]:
                steps=[s for s in matches[0].get("steps",[]) if s.get("name")==step_name]
                if len(steps)!=1 or steps[0].get("conclusion")!="success":raise SystemExit("required step missing/skipped/failed: "+step_name)
        evidence.append(latest_run["html_url"])
    tag=policy["tag"]
    # Retry may recover a same-SHA tag left by an interrupted publication.
    # Never replace another tag/release or resolve identity from a mutable ref.
    try:
        existing=api("/git/ref/tags/"+tag)
    except urllib.error.HTTPError as error:
        if error.code!=404:raise
        existing=None
    if existing is not None and (existing.get("object",{}).get("type")!="commit" or existing["object"].get("sha")!=head):
        raise SystemExit("preview tag belongs to another candidate; no replacement permitted")
    if existing is not None:
        try:published=api("/releases/tags/"+tag)
        except urllib.error.HTTPError as error:
            if error.code!=404:raise
        else:
            if published.get("prerelease") is not True or head not in published.get("body",""):
                raise SystemExit("existing release metadata requires manual review")
            print(json.dumps({"published":True,"alreadyPublished":True,"sourceCommit":head,"releaseUrl":published["html_url"]}));return
    if api("/branches/main")["commit"]["sha"]!=head:raise SystemExit("main changed during release verification")
    body="Developer preview at `"+head+"`.\n\nHuman review: "+approved[0]["html_url"]+"\n\nExact post-merge CI:\n"+"\n".join("- "+url for url in evidence)+"\n\nPer-path licenses remain in force. RTOS reference/simulation is not a hardware safety or timing qualification. No banking production certification is asserted."
    if existing is None:api("/git/refs",{"ref":"refs/tags/"+tag,"sha":head})
    if api("/git/ref/tags/"+tag).get("object",{}).get("sha")!=head:raise SystemExit("tag identity changed; publication stopped")
    release=api("/releases",{"tag_name":tag,"target_commitish":head,"name":tag,"body":body,"draft":False,"prerelease":True})
    print(json.dumps({"published":True,"sourceCommit":head,"releaseUrl":release["html_url"]}))

if __name__=="__main__":main()
