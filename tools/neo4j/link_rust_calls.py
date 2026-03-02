from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
AUTH = ("neo4j", "password")

def link_rust_calls():
    driver = GraphDatabase.driver(URI, auth=AUTH)
    
    query = """
    MATCH (c:CALL:Rust), (m:METHOD:Rust)
    WHERE c.name = m.full_name
       OR (c.name CONTAINS "::" AND m.full_name ENDS WITH c.name)
       OR (c.name = m.name)
    MERGE (c)-[:CALL]->(m)
    RETURN count(c) as count
    """
    
    # We need to be careful not to over-link (e.g. methods with same name in different crates).
    # But for this analysis, we can be a bit aggressive.
    # Ideally, we should match `crate_name::module::func` to `crate_name::module::func`.
    
    # Improved query:
    # 1. Exact match full_name
    # 2. If call has "crate::foo", match method with "foo" in package "crate" (if we had package info on methods)
    # The current dataset has `full_name` like `entry` (in crate_a).
    # The call in main is `crate_a::entry`.
    
    # So we should match if `c.name` ends with `m.full_name`? No.
    # `crate_a::entry` ends with `entry`.
    
    query_aggressive = """
    MATCH (c:CALL:Rust), (m:METHOD:Rust)
    WHERE NOT (c)-[:CALL]->(:METHOD)
      AND NOT c.name STARTS WITH "<"
      AND (
           c.name = m.full_name
        OR c.name = m.name
        OR (c.name CONTAINS "::" AND c.name ENDS WITH "::" + m.name)
      )
    MERGE (c)-[:CALL]->(m)
    RETURN c.name, m.full_name
    """

    with driver.session() as session:
        result = session.run(query_aggressive)
        count = 0
        for r in result:
            # print(f"Linked {r['c.name']} -> {r['m.full_name']}")
            count += 1
        print(f"Linked {count} Rust-to-Rust calls.")

    driver.close()

if __name__ == "__main__":
    link_rust_calls()
