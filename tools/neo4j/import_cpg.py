from neo4j import GraphDatabase
import json
import argparse
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.neo4j.config import neo4j_auth, neo4j_uri

DEFAULT_BATCH_SIZE = 1000
DEFAULT_CLEAR_BATCH_SIZE = 10000


def chunked(items, size):
    for idx in range(0, len(items), size):
        yield items[idx: idx + size]


def clear_database_batched(session, batch_size=DEFAULT_CLEAR_BATCH_SIZE):
    print(f"Clearing database in batches of {batch_size} nodes...")
    total_deleted = 0
    while True:
        result = session.run(
            f"MATCH (n) WITH n LIMIT {int(batch_size)} DETACH DELETE n RETURN count(n) AS deleted"
        )
        deleted = int(result.single()["deleted"])
        total_deleted += deleted
        if deleted == 0:
            break
        print(f"Cleared {total_deleted} nodes...")
    print(f"Database clear finished; deleted {total_deleted} nodes.")


def import_json_to_neo4j(json_file, clear_db, id_offset, label_tag):
    driver = GraphDatabase.driver(neo4j_uri(), auth=neo4j_auth())

    with open(json_file, 'r') as f:
        data = json.load(f)

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    print(f"Loading {len(nodes)} nodes and {len(edges)} edges from {json_file}")
    if label_tag:
        print(f"Applying label tag: :{label_tag}")
    print(f"Applying ID offset: {id_offset}")

    with driver.session() as session:
        # Optional: Clear database
        if clear_db:
            clear_database_batched(session)
        else:
            print("Incremental import (DB not cleared).")

        if label_tag:
            try:
                session.run(f"CREATE INDEX node_id_{label_tag.lower()} IF NOT EXISTS FOR (n:{label_tag}) ON (n.id)")
                print(f"Ensured index: :{label_tag}(id)")
            except Exception as exc:
                print(f"[WARN] Failed to create index on :{label_tag}(id): {exc}")

        # Import Nodes (grouped by labels for batched UNWIND import)
        print(f"Importing {len(nodes)} nodes...")
        nodes_by_label = defaultdict(list)
        for node in nodes:
            original_id = node["id"]
            new_id = original_id + id_offset
            props = {k: v for k, v in node.items() if k not in {"id", "label"}}
            props["id"] = new_id
            props["original_id"] = original_id

            labels = [node["label"]]
            if label_tag:
                labels.append(label_tag)
            label_str = ":".join(labels)
            nodes_by_label[label_str].append({"id": new_id, "props": props})

        node_query_template = "UNWIND $rows AS row MERGE (n:{labels} {{id: row.id}}) SET n += row.props"
        for labels, rows in nodes_by_label.items():
            query = node_query_template.format(labels=labels)
            for batch in chunked(rows, DEFAULT_BATCH_SIZE):
                session.run(query, rows=batch)

        # Import Edges (grouped by edge type for batched UNWIND import)
        print(f"Importing {len(edges)} edges...")
        edges_by_type = defaultdict(list)
        for edge in edges:
            src_id = edge['src'] + id_offset
            dst_id = edge['dst'] + id_offset
            edge_type = edge['label']
            props = edge.get('properties', {})
            edges_by_type[edge_type].append({
                "src_id": src_id,
                "dst_id": dst_id,
                "props": props,
            })

        node_match = "(a {id: row.src_id}), (b {id: row.dst_id})"
        if label_tag:
            node_match = f"(a:{label_tag} {{id: row.src_id}}), (b:{label_tag} {{id: row.dst_id}})"

        edge_query_template = (
            "UNWIND $rows AS row "
            f"MATCH {node_match} "
            "CREATE (a)-[r:`__EDGE_TYPE__`]->(b) "
            "SET r += row.props"
        )
        for edge_type, rows in edges_by_type.items():
            query = edge_query_template.replace("__EDGE_TYPE__", edge_type)
            for batch in chunked(rows, DEFAULT_BATCH_SIZE):
                session.run(query, rows=batch)

    driver.close()
    print("Import finished successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import CPG JSON into Neo4j")
    parser.add_argument("json_file", help="Path to the JSON file containing nodes and edges")
    parser.add_argument("--clear", action="store_true", help="Clear the database before importing")
    parser.add_argument("--offset", type=int, default=0, help="Integer offset to add to all node IDs (default: 0)")
    parser.add_argument("--label", type=str, default="", help="Additional label to add to all nodes (e.g. 'C' or 'Rust')")
    
    args = parser.parse_args()
    
    import_json_to_neo4j(args.json_file, args.clear, args.offset, args.label)
