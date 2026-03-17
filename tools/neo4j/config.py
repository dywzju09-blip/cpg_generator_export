import os


def neo4j_uri() -> str:
    return os.environ.get("CPG_NEO4J_URI", "bolt://localhost:7687")


def neo4j_auth() -> tuple[str, str]:
    user = os.environ.get("CPG_NEO4J_USER", "neo4j")
    password = os.environ.get("CPG_NEO4J_PASSWORD", "password")
    return (user, password)
