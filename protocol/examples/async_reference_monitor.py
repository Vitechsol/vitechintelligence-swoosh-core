"""Async structured-action integration over Halibut's canonical Rust-backed local broker.
Synthetic test fixture only. See contracts/v1/README.md for profile and run instructions.
"""
import argparse
import asyncio
import json
from pathlib import Path
from halibut_core import LocalRuntime, RustAuthority, Denied

async def observable_events(effect):
    # A future model adapter may emit visible text and structured tool proposals.
    # These are never authenticated principal, role, approval, or policy inputs.
    yield {"kind":"visible_text","text":"Preparing the synthetic local record."}
    await asyncio.sleep(0)
    yield {"kind":"action_proposal","result":effect}

async def main(args):
    request=json.loads((args.fixture/"host-request.json").read_text())
    authority=RustAuthority(args.trust_console,args.fixture/"current.tpack",(args.fixture/"checkpoint.txt").read_text().strip(),
        request["authenticated_subject"],"industrial.demo",1)
    runtime=LocalRuntime(args.database,authority,"industrial.demo")
    envelope=args.fixture/"action.bin";effect=json.loads((args.fixture/"effect.json").read_text());binding=request["binding"];task=binding["task_id"]
    # Only fixture-controlled host configuration supplies identity, destination and assignment.
    stream=None
    try:
        runtime.admit(task,binding["workflow_id"],request["resource"],request["action"],binding["purpose"],binding["destination"],effect)
        generation=runtime.assign(task);handle=runtime.authorize(task,generation,envelope)
        stream=observable_events(effect)
        async for event in stream:
            if event["kind"]=="visible_text":print(event["text"])
            elif event["kind"]=="action_proposal":
                result=event["result"]
                runtime.produced(task,generation,result);runtime.validate(task,generation,result)
                # Authorization is re-evaluated immediately before the atomic local effect.
                commit=runtime.commit(handle,envelope,result)
                print(json.dumps({"state":"CLOSED","commitRef":commit,"auditVerified":runtime.verify_audit()}))
            else:raise Denied("UNKNOWN_STREAM_EVENT")
    except (Denied,asyncio.CancelledError):
        try:runtime.cancel(task)
        except Denied:pass
        raise
    finally:
        if stream is not None:await stream.aclose()
        runtime.close()

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--trust-console",type=Path,required=True);parser.add_argument("--fixture",type=Path,required=True);parser.add_argument("--database",type=Path,required=True)
    asyncio.run(main(parser.parse_args()))
