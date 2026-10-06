"""Thin interoperability validation. These documents never grant authority."""
from datetime import datetime
from importlib.resources import files
import json
from jsonschema import Draft202012Validator, FormatChecker

MAX_DOCUMENT_BYTES = 65_536
SCHEMA = json.loads(files(__package__).joinpath("schemas/v1/contracts.schema.json").read_text())

class ContractError(ValueError):
    pass

def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ContractError("DUPLICATE_FIELD")
        value[key] = item
    return value

def _constant(value):
    raise ContractError("NONFINITE_NUMBER")

CHECKER = FormatChecker()
@CHECKER.checks("date-time", raises=(ValueError, TypeError))
def _time(value):
    if not isinstance(value, str): return True
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return True

def _period(value, start, end, maximum=None):
    first = datetime.fromisoformat(value[start].replace("Z", "+00:00"))
    last = datetime.fromisoformat(value[end].replace("Z", "+00:00"))
    duration = (last-first).total_seconds()
    if duration <= 0 or (maximum is not None and duration > maximum):
        raise ContractError("TIME_BOUNDS_INVALID")

def _semantics(name, value):
    if name == "GovernedContext": _period(value, "createdAt", "expiresAt")
    if name in {"CapabilityDescriptor", "ApprovalEvidence"}: _period(value, "issuedAt", "expiresAt", 600)
    if name == "TaskExecution" and value["attempt"] > value["maxAttempts"]:
        raise ContractError("RETRY_BUDGET_INVALID")
    if name == "Packet":
        context, intent, capability = value["context"], value["intent"], value["capability"]
        _semantics("GovernedContext", context); _semantics("CapabilityDescriptor", capability)
        if intent["contextId"] != context["contextId"] or capability["contextId"] != context["contextId"]:
            raise ContractError("CONTEXT_BINDING_MISMATCH")
        if any(intent[key] != capability[key] for key in ("workflowId","taskId","generation","resource","action","purpose","destination","effectDigest")):
            raise ContractError("ACTION_BINDING_MISMATCH")
        if intent["resource"] not in context["resourceScopes"] or intent["purpose"] != context["purpose"]:
            raise ContractError("CONTEXT_SCOPE_MISMATCH")
        if any(capability[key] != context[key] for key in ("policyVersion","trustEpoch")):
            raise ContractError("CONTEXT_STATE_MISMATCH")
        if datetime.fromisoformat(capability["expiresAt"].replace("Z","+00:00")) > datetime.fromisoformat(context["expiresAt"].replace("Z","+00:00")):
            raise ContractError("CONTEXT_EXPIRY_EXCEEDED")

def decode(name: str, document: bytes) -> dict:
    if name not in SCHEMA["$defs"]: raise ContractError("UNSUPPORTED_CONTRACT")
    if not isinstance(document, bytes) or len(document) > MAX_DOCUMENT_BYTES:
        raise ContractError("DOCUMENT_TOO_LARGE_OR_INVALID")
    try:
        value = json.loads(document.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ContractError("INVALID_JSON") from error
    schema = {**SCHEMA, "$ref":"#/$defs/"+name}
    if not Draft202012Validator(schema, format_checker=CHECKER).is_valid(value):
        raise ContractError("SCHEMA_MISMATCH")
    _semantics(name, value)
    return value
