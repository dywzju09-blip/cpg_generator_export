from neo4j import GraphDatabase
import re

URI = "bolt://localhost:7687"
AUTH = ("neo4j", "password")

def patch_missing_calls():
    driver = GraphDatabase.driver(URI, auth=AUTH)
    
    # e.g. "terminator: Some(Terminator { ... kind: _5 = crate_a::entry(...) ... })"
    call_pattern = re.compile(r"kind:\s*(?:_\d+\s*=\s*)?([a-zA-Z0-9_:]+)\(")

    # Get ALL blocks that might have a terminator call
    query_blocks = """
    MATCH (b:BLOCK:Rust)
    WHERE b.code CONTAINS "kind:"
    RETURN b.id AS id, b.code AS code, b.line_number AS line
    """

    check_call_exists_query = """
    MATCH (b:BLOCK:Rust {id: $block_id})-[:AST]->(c:CALL)
    WHERE c.name = $name
    RETURN count(c) > 0 AS exists
    """

    create_call_query = """
    MATCH (b:BLOCK:Rust {id: $block_id})
    CREATE (c:CALL:Rust {
        id: $call_id,
        name: $name,
        method_full_name: $name,
        code: $code,
        line_number: $line,
        label: "CALL"
    })
    MERGE (b)-[:AST]->(c)
    MERGE (b)-[:CFG]->(c)
    """

    with driver.session() as session:
        blocks = session.run(query_blocks)
        
        count = 0
        for record in blocks:
            code = record["code"]
            match = call_pattern.search(code)
            if match:
                name = match.group(1)
                
                # Filter out internal things or non-functions if possible
                if "std::" in name or "core::" in name or "<" in name:
                    continue
                
                # Check if this call already exists as a node
                result = session.run(check_call_exists_query, block_id=record["id"], name=name)
                if result.single()["exists"]:
                    continue
                
                print(f"Patching block {record['id']} -> Call to {name}")
                
                call_id = record["id"] + 500000000 # Offset
                
                session.run(create_call_query, 
                            block_id=record["id"], 
                            call_id=call_id, 
                            name=name, 
                            code=name + "(...)", 
                            line=record["line"])
                count += 1
                
        print(f"Patched {count} missing CALL nodes.")

    driver.close()

if __name__ == "__main__":
    patch_missing_calls()
