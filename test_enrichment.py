import json
from pathlib import Path
from get_context import get_context

BASE_DIR = Path(__file__).resolve().parent

with open(
    BASE_DIR / "test_alert.json",
    encoding="utf-8"
) as file:
    alert = json.load(file)

rule_id = alert["rule"]["id"]
context = get_context(rule_id)

result = {
    "alert": alert,
    "retrieved_context": context
}

print(json.dumps(
    result,
    indent=2,
    ensure_ascii=False
))
