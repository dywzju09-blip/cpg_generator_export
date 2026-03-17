from neo4j import GraphDatabase
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.neo4j.config import neo4j_auth, neo4j_uri

def verify_taint():
    driver = GraphDatabase.driver(neo4j_uri(), auth=neo4j_auth())
    with driver.session() as session:
        print("[*] Debugging LITERALS...")
        res = session.run("""
            MATCH (l:LITERAL)
            RETURN l.code as code
            LIMIT 5
        """).data()
        for r in res:
            print(f"  - {r['code']}")

        print("[*] Finding source payload (broader search)...")
        # Try finding by 'const' prefix which Rust CPG seems to use
        res = session.run("""
            MATCH (l:LITERAL)
            WHERE l.code CONTAINS "const" AND l.code CONTAINS "key"
            RETURN l.id as id, l.code as code
        """).data()
        
        if not res:
            print("[-] Source payload not found!")
            return
        
        source_id = res[0]['id']
        print(f"[+] Found source literal: {source_id} ({res[0]['code'][:20]}...)")

        print("[*] Finding sink call (process_data)...")
        res = session.run("""
            MATCH (c:CALL)
            WHERE c.name = "process_data"
            RETURN c.id as id, c.code as code
        """).data()
        
        if not res:
            print("[-] Sink call not found!")
            return
            
        sink_id = res[0]['id']
        print(f"[+] Found sink call: {sink_id}")

        print("[*] Checking for data flow path...")
        # Use AST or CFG first to ensure connectivity, then refined
        res = session.run("""
            MATCH (source), (sink)
            WHERE id(source) = $src AND id(sink) = $dst
            MATCH p = shortestPath((source)-[:AST|CFG|DDG*0..50]->(sink))
            RETURN length(p) as len
        """, src=source_id, dst=sink_id).data()
        
        if res:
            print(f"[+] Path found! Length: {res[0]['len']}")
        else:
            print("[-] No path found.")

    driver.close()

if __name__ == "__main__":
    verify_taint()
