from neo4j import GraphDatabase
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.neo4j.config import neo4j_auth, neo4j_uri

def link_callbacks():
    driver = GraphDatabase.driver(neo4j_uri(), auth=neo4j_auth())
    
    # 1. Cache all Method names
    # We want to be careful about common names.
    # Let's count method name frequency to exclude extremely common ones if needed, 
    # but for now let's just exclude a hardcoded blocklist.
    print("Fetching methods...")
    method_query = """
    MATCH (m:METHOD)
    WHERE NOT m.name IN ['main', 'new', 'init', 'drop', 'unwrap', 'as_ptr', 'len', 'as_mut_ptr']
      AND NOT m.name CONTAINS "<"
      AND NOT m.name CONTAINS "operator"
    RETURN id(m) as mid, m.name
    """
    
    methods = {} # name -> list of ids
    with driver.session() as session:
        for r in session.run(method_query):
            name = r['m.name']
            if name not in methods:
                methods[name] = []
            methods[name].append(r['mid'])
            
    print(f"Found {len(methods)} unique method names.")
    
    # 2. Fetch all CALLs
    print("Fetching calls...")
    call_query = "MATCH (c:CALL) RETURN id(c) as cid, c.name, c.code"
    
    links = []
    
    # Regex to extract args from "func(arg1, arg2)"
    # This is a simple parser that assumes function pointers are top-level args.
    # e.g. "XML_SetExternalEntityRefHandler(parser, external_entity_handler)"
    
    with driver.session() as session:
        calls = session.run(call_query)
        for r in calls:
            c_id = r['cid']
            c_name = r['c.name']
            c_code = r['c.code']
            
            if not c_code or "(" not in c_code:
                continue
                
            # Extract content inside last parentheses pair to handle nested calls loosely
            # "foo(bar)" -> "bar"
            # "foo(a, b)" -> "a, b"
            try:
                # Find the first '(' and the last ')'
                start = c_code.find('(')
                end = c_code.rfind(')')
                if start == -1 or end == -1 or end <= start:
                    continue
                
                args_str = c_code[start+1:end]
                # Split by comma
                # Note: this might split "func(a,b)" incorrectly if used as arg, 
                # but function pointers are usually simple identifiers.
                args = [a.strip() for a in args_str.split(',')]
                
                for arg in args:
                    # Clean up arg (remove & if address of)
                    clean_arg = arg
                    if clean_arg.startswith('&'):
                        clean_arg = clean_arg[1:].strip()
                    
                    if clean_arg in methods:
                        # Found a match!
                        # Link this call to all methods with this name (usually just one in C)
                        for m_id in methods[clean_arg]:
                            if c_id != m_id: # Don't link self
                                links.append((c_id, m_id, clean_arg))
            except Exception as e:
                # print(f"Error parsing code: {c_code} - {e}")
                pass

    # 3. Create links
    print(f"Found {len(links)} potential callback links.")
    
    link_query = """
    MATCH (c:CALL), (m:METHOD)
    WHERE id(c) = $c_id AND id(m) = $m_id
    MERGE (c)-[:CALLBACK_REG]->(m)
    MERGE (c)-[:CALL]->(m)
    """
    
    with driver.session() as session:
        count = 0
        for c_id, m_id, name in links:
            print(f"Linking {c_id} -> {m_id} ({name})")
            session.run(link_query, c_id=c_id, m_id=m_id)
            count += 1
        print(f"Created {count} links.")

    driver.close()

if __name__ == "__main__":
    link_callbacks()
