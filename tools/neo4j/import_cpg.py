from neo4j import GraphDatabase
import json
import argparse
import sys

# Neo4j configuration
URI = "bolt://localhost:7687"
AUTH = ("neo4j", "password")  # Change if you have a password

def import_json_to_neo4j(json_file, clear_db, id_offset, label_tag):
    driver = GraphDatabase.driver(URI, auth=AUTH)

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
            print("Clearing database...")
            session.run("MATCH (n) DETACH DELETE n")
        else:
            print("Incremental import (DB not cleared).")

        # Import Nodes
        print(f"Importing {len(nodes)} nodes...")
        for node in nodes:
            # Shift ID
            original_id = node['id']
            new_id = original_id + id_offset
            
            # Prepare properties
            props = {k: v for k, v in node.items() if k != 'id' and k != 'label'}
            props['id'] = new_id
            props['original_id'] = original_id # Keep track of original ID
            
            # Construct labels: Original Label + Optional Tag
            labels = [node['label']]
            if label_tag:
                labels.append(label_tag)
            
            label_str = ":".join(labels)
            
            # Use MERGE to avoid duplicates if re-running without clear
            query = f"MERGE (n:{label_str} {{id: $id}}) SET n += $props"
            session.run(query, id=new_id, props=props)

        # Import Edges
        print(f"Importing {len(edges)} edges...")
        for edge in edges:
            src_id = edge['src'] + id_offset
            dst_id = edge['dst'] + id_offset
            edge_type = edge['label']
            props = edge.get('properties', {})
            
            # Create relationship with properties
            query = (
                f"MATCH (a {{id: $src_id}}), (b {{id: $dst_id}}) "
                f"MERGE (a)-[r:`{edge_type}`]->(b) "
                f"SET r += $props"
            )
            session.run(query, src_id=src_id, dst_id=dst_id, props=props)

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
