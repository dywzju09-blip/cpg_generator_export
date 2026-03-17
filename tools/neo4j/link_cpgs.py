from neo4j import GraphDatabase
import json
import os
import argparse
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.neo4j.config import neo4j_auth, neo4j_uri

def link_cpgs(log_file):
    driver = GraphDatabase.driver(neo4j_uri(), auth=neo4j_auth())
    
    # Link Rust CALL to C METHOD with multiple heuristics:
    # 1) exact name match
    # 2) method_full_name match
    # 3) code contains callee name (fallback)
    # Exclude operator/internal names to reduce false positives.
    cypher_query = """
    MATCH (r:CALL:Rust), (c:METHOD:C)
    WHERE NOT r.name STARTS WITH "<"
      AND NOT r.name STARTS WITH "operator"
      AND NOT c.name STARTS WITH "<"
      AND NOT c.name STARTS WITH "operator"
      AND (
           r.name = c.name
        OR r.method_full_name = c.name
        OR r.code CONTAINS c.name
      )
    MERGE (r)-[rel:FFI_CALL]->(c)
    RETURN r.id AS source_id, r.name AS source_name, c.id AS target_id, c.name AS target_name, type(rel) AS rel_type
    """

    # Link C CALL to C METHOD by name to reconstruct C->C call edges
    # (needed when C components are imported separately).
    c_call_query = """
    MATCH (c:CALL:C), (m:METHOD:C)
    WHERE NOT c.name STARTS WITH "<"
      AND NOT c.name STARTS WITH "operator"
      AND NOT m.name STARTS WITH "<"
      AND NOT m.name STARTS WITH "operator"
      AND (
           c.name = m.name
        OR (c.full_name IS NOT NULL AND m.full_name IS NOT NULL AND c.full_name = m.full_name)
      )
    MERGE (c)-[rel:CALL]->(m)
    RETURN c.id AS source_id, c.name AS source_name, m.id AS target_id, m.name AS target_name, type(rel) AS rel_type
    """
    
    linked_edges = []
    
    with driver.session() as session:
        print("Executing linking query...")
        result = session.run(cypher_query)
        
        count = 0
        for record in result:
            edge_info = {
                "source_id": record["source_id"],
                "source_name": record["source_name"],
                "target_id": record["target_id"],
                "target_name": record["target_name"],
                "type": record["rel_type"],
                "timestamp": datetime.now().isoformat()
            }
            linked_edges.append(edge_info)
            count += 1
            
        print(f"Created/Verified {count} FFI links between Rust and C nodes.")

        print("Executing C->C call linking query...")
        result = session.run(c_call_query)

        count = 0
        for record in result:
            edge_info = {
                "source_id": record["source_id"],
                "source_name": record["source_name"],
                "target_id": record["target_id"],
                "target_name": record["target_name"],
                "type": record["rel_type"],
                "timestamp": datetime.now().isoformat()
            }
            linked_edges.append(edge_info)
            count += 1

        print(f"Created/Verified {count} C->C CALL links.")

    driver.close()
    
    # Log to JSON
    if linked_edges:
        # Append to existing log if exists, or create new
        existing_logs = []
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    existing_logs = json.load(f)
            except:
                pass
        
        existing_logs.extend(linked_edges)
        
        with open(log_file, 'w') as f:
            json.dump(existing_logs, f, indent=2)
        print(f"Linking details logged to {log_file}")
    else:
        print("No new links created or found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Link Rust and C CPGs in Neo4j")
    parser.add_argument("--log", default="output/linking_log.json", help="Path to log file for linked edges")
    args = parser.parse_args()
    
    link_cpgs(args.log)
