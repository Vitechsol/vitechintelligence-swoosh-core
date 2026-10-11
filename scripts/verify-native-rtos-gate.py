#!/usr/bin/env python3
"""Canonical pinned V3 ALLOW -> protected C gate, without another trust verifier.

Synthetic host conformance only. The generated admission is NOT a transport token.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--tools",type=Path,required=True)
    parser.add_argument("--source-commit",required=True)
    args=parser.parse_args()
    tools=args.tools.resolve()
    manifest=json.loads((tools/"manifest.json").read_text())
    if len(args.source_commit)!=40 or any(c not in "0123456789abcdef" for c in args.source_commit) or manifest.get("sourceCommit")!=args.source_commit or manifest.get("platform")!="linux-x86_64" or manifest.get("purpose")!="synthetic-native-conformance":
        raise RuntimeError("artifact source/platform/purpose mismatch")
    for name in ("trust-console","halibut-fixture"):
        if hashlib.sha256((tools/name).read_bytes()).hexdigest()!=manifest.get("sha256",{}).get(name):
            raise RuntimeError("artifact digest mismatch")
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="swoosh-v3-rtos-") as directory:
        work=Path(directory)
        subprocess.run([str(tools/"halibut-fixture"),str(work)],check=True,capture_output=True,text=True,timeout=10)
        request=json.loads((work/"host-request.json").read_text())
        command=[str(tools/"trust-console"),"evaluate-action-v3","--envelope",str(work/"action.bin"),"--trust-pack",str(work/"current.tpack"),"--expected-checkpoint",(work/"checkpoint.txt").read_text().strip(),"--minimum-epoch","1","--host-request",str(work/"host-request.json")]
        result=subprocess.run(command,check=True,capture_output=True,text=True,timeout=10)
        receipt=json.loads(result.stdout)
        if receipt.get("profile_version")!=3 or receipt.get("trust",{}).get("decision")!="ALLOW":
            raise RuntimeError("canonical V3 ALLOW required")
        binding=request["binding"]
        if receipt["trust"]["policy_version"]!=binding["policy_version"] or receipt["trust"]["trust_epoch"]!=binding["trust_epoch"]:
            raise RuntimeError("unexpected verified trust state")
        remaining=receipt["trust"]["valid_until"]-int(time.time())
        if remaining<=0:raise RuntimeError("expired native authority")
        def values(value):
            if not isinstance(value,list) or len(value)!=32 or not any(value) or not all(type(v)is int and 0<=v<256 for v in value):
                raise RuntimeError("invalid protected commitment")
            return "{"+",".join(map(str,value))+"}"
        def commitment(domain,fields):
            return list(hashlib.sha256(domain+json.dumps(fields,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).digest())
        boot=list(hashlib.sha256(b"synthetic-test-boot-session").digest())
        task=commitment(b"SWOOSH\0rtos-task\0v1\0",[receipt["trust"]["trust_domain"],binding["workflow_id"],binding["task_id"]])
        role=commitment(b"SWOOSH\0rtos-role\0v1\0",binding["role_id"])
        scope=",\n".join("."+key+"="+values(value) for key,value in {"boot_nonce":boot,"task_tag":task,"subject":request["authenticated_subject"],"role_digest":role,"action_digest":receipt["action_digest"],"effect_digest":binding["effect_digest"]}.items())
        scope+=",\n.generation="+str(binding["generation"])+",.policy_version="+str(binding["policy_version"])+",.trust_epoch="+str(binding["trust_epoch"])
        source='''#include "swoosh_gate.h"
#include <assert.h>
#include <stdio.h>
static unsigned effects;
static SwooshStatus dispatch(void *unused,const SwooshRequest *request) {(void)unused;(void)request;++effects;return SWOOSH_OK;}
int main(void) {
SwooshVerifiedAdmission verified={.scope={__ADMISSION_SCOPE__},.expires_tick=EXPIRY};
SwooshGate gate;
assert(swoosh_gate_init(&gate,verified.scope.boot_nonce,verified.scope.policy_version,verified.scope.trust_epoch,100,1000)==SWOOSH_OK);
assert(swoosh_gate_resume_locked(&gate)==SWOOSH_OK);
assert(swoosh_gate_admit_verified_locked(&gate,&verified,1000)==SWOOSH_OK);
SwooshRequest changed=verified.scope;changed.effect_digest[0]^=1;
assert(swoosh_gate_execute_locked(&gate,&changed,1000,dispatch,NULL)==SWOOSH_SCOPE_MISMATCH);
assert(effects==0);
assert(swoosh_gate_execute_locked(&gate,&verified.scope,1000,dispatch,NULL)==SWOOSH_OK);
assert(swoosh_gate_execute_locked(&gate,&verified.scope,1000,dispatch,NULL)==SWOOSH_REPLAY);
assert(effects==1);swoosh_gate_halt_locked(&gate);
assert(swoosh_gate_execute_locked(&gate,&verified.scope,1000,dispatch,NULL)==SWOOSH_HALTED);
puts("Canonical V3 to bounded RTOS gate: PASS");return 0;}
'''.replace("__ADMISSION_SCOPE__",scope).replace("EXPIRY",str(1000+min(100,remaining)))
        (work/"bridge.c").write_text(source)
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror","-pedantic","-O2","-I"+str(root/"rtos/include"),str(root/"rtos/src/swoosh_gate.c"),str(work/"bridge.c"),"-o",str(work/"bridge")],check=True,capture_output=True,text=True,timeout=20)
        probe=subprocess.run([str(work/"bridge")],check=True,capture_output=True,text=True,timeout=10)
        print(json.dumps({"status":"PASS","sourceCommit":args.source_commit,"canonicalV3Allow":True,"effects":1,"changedEffectDenied":True,"replayDenied":True,"haltDenied":True,"scope":"synthetic-host-conformance","gateOutput":probe.stdout.strip()}))

if __name__=="__main__":main()
