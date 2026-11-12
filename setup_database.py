import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "database_context.db"

DOC_TESTS = (
    "https://documentation.wazuh.com/current/"
    "user-manual/ruleset/testing.html"
)

DOC_RULES = (
    "https://documentation.wazuh.com/current/"
    "user-manual/ruleset/rules/custom.html"
)

DOC_FIM = (
    "https://documentation.wazuh.com/current/"
    "user-manual/capabilities/malware-detection/"
    "fim-threat-detection-rules.html"
)

rules = [
    (
        "5710",
        "Usuário SSH inexistente",
        "sshd: Attempt to login using a non-existent user",
        5,
        "Tentativa de autenticação SSH com um nome "
        "de usuário que não existe no sistema. "
        "Um evento isolado não confirma ataque.",
        DOC_TESTS,
        "documentada; validar no laboratório"
    ),
    (
        "5712",
        "Tentativas repetidas de autenticação SSH",
        "sshd: brute force trying to get access to the system",
        None,
        "Regra de correlação relacionada a tentativas "
        "repetidas de autenticação SSH. Verificar "
        "os eventos associados antes de concluir "
        "que houve uma invasão.",
        DOC_TESTS,
        "documentada; validar no laboratório"
    ),
    (
        "550",
        "Alteração de integridade de arquivo",
        "Integrity checksum changed.",
        7,
        "O monitoramento de integridade detectou "
        "alteração em um arquivo monitorado. "
        "A mudança pode ser legítima ou suspeita, "
        "dependendo das evidências adicionais.",
        DOC_FIM,
        "documentada; validar no laboratório"
    )
]

mitre_associations = [
    ("5710", "T1110.001", DOC_TESTS),
    ("5710", "T1021.004", DOC_TESTS),
    ("5710", "T1078", DOC_TESTS),
    ("550", "T1565.001", DOC_FIM)
]

def create_database():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS wazuh_rules (
                rule_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                reference_level INTEGER,
                context TEXT NOT NULL,
                source_url TEXT NOT NULL,
                validation_status TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS mitre_rules (
                rule_id TEXT NOT NULL,
                mitre_id TEXT NOT NULL,
                source_url TEXT NOT NULL,
                PRIMARY KEY (rule_id, mitre_id),
                FOREIGN KEY (rule_id)
                    REFERENCES wazuh_rules(rule_id)
            )
        """)

        conn.executemany("""
            INSERT OR IGNORE INTO wazuh_rules
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, rules)

        conn.executemany("""
            INSERT OR IGNORE INTO mitre_rules
            VALUES (?, ?, ?)
        """, mitre_associations)

    print(f"Banco criado: {DB_PATH}")

if __name__ == "__main__":
    create_database()
