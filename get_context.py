import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "database_context.db"

def get_context(rule_id):
    with sqlite3.connect(
        f"file:{DB_PATH}?mode=ro", uri=True
    ) as conn:
        conn.row_factory = sqlite3.Row

        rule = conn.execute("""
            SELECT * FROM wazuh_rules
            WHERE rule_id = ?
        """, (str(rule_id),)).fetchone()

        if rule is None:
            return None

        techniques = conn.execute("""
            SELECT mitre_id
            FROM mitre_rules
            WHERE rule_id = ?
        """, (str(rule_id),)).fetchall()

        result = dict(rule)
        result["mitre_ids"] = [
            item["mitre_id"] for item in techniques
        ]

        return result

if __name__ == "__main__":
    import json

    context = get_context("5710")
    print(json.dumps(
        context,
        indent=2,
        ensure_ascii=False
    ))
