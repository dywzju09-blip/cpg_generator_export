import os
import glob
import json
import argparse
import xml.etree.ElementTree as ET

def parse_graphml_file(filepath, node_filter, edge_filter):
    nodes = []
    edges = []
    
    # Namespaces in GraphML can be tricky.
    # Joern's export typically uses: http://graphml.graphdrawing.org/xmlns
    ns = {'g': 'http://graphml.graphdrawing.org/xmlns'}
    
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        
        # Find all keys to map IDs to Attribute Names
        keys = {}
        for key in root.findall('g:key', ns):
            attr_id = key.get('id')
            attr_name = key.get('attr.name')
            keys[attr_id] = attr_name
            
        for graph in root.findall('g:graph', ns):
            
            # Nodes
            for node_elem in graph.findall('g:node', ns):
                node_id = int(node_elem.get('id'))
                node_data = {"id": node_id}
                
                # Extract attributes
                for data in node_elem.findall('g:data', ns):
                    key_ref = data.get('key')
                    attr_name = keys.get(key_ref)
                    if attr_name:
                        node_data[attr_name] = data.text
                
                label = node_data.get('labelV', 'UNKNOWN')
                
                # Apply Node Filter
                if not node_filter(label):
                    continue

                # Normalize keys
                normalized_node = {
                    "id": node_id,
                    "label": label,
                    "code": node_data.get('CODE', ''),
                    "line_number": None
                }
                
                if 'LINE_NUMBER' in node_data:
                    try:
                        normalized_node['line_number'] = int(node_data['LINE_NUMBER'])
                    except:
                        pass

                if 'NAME' in node_data:
                    normalized_node['name'] = node_data['NAME']
                if 'FULL_NAME' in node_data:
                    normalized_node['full_name'] = node_data['FULL_NAME']
                
                # Extract Apron attributes if present
                for attr in ['apron_value_range', 'apron_buffer_size', 'apron_pointer_offset', 'apron_allocation_kind']:
                    if attr in node_data:
                        normalized_node[attr] = node_data[attr]
                    # Also try capitalized version which Joern might use
                    elif attr.upper() in node_data:
                        normalized_node[attr] = node_data[attr.upper()]
                
                if 'name' not in normalized_node:
                    normalized_node['name'] = normalized_node['code']

                nodes.append(normalized_node)
            
            # Edges
            for edge_elem in graph.findall('g:edge', ns):
                src = int(edge_elem.get('source'))
                dst = int(edge_elem.get('target'))
                
                edge_label = "UNKNOWN"
                for data in edge_elem.findall('g:data', ns):
                    key_ref = data.get('key')
                    attr_name = keys.get(key_ref)
                    if attr_name == 'labelE':
                        edge_label = data.text
                        break
                
                # Apply Edge Filter
                if not edge_filter(edge_label):
                    continue

                edges.append({
                    "src": src,
                    "dst": dst,
                    "label": edge_label
                })
                
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        
    return nodes, edges

def create_filter(include_list, exclude_list):
    """
    Returns a function that takes a type string and returns True if it should be included.
    Logic:
    - If include_list is provided, ONLY items in it are kept.
    - If exclude_list is provided, items in it are dropped.
    - If both, include_list takes precedence (intersection logic usually, but here we do: must be in include AND not in exclude).
    """
    def filter_func(item_type):
        if include_list and item_type not in include_list:
            return False
        if exclude_list and item_type in exclude_list:
            return False
        return True
    return filter_func

def convert_all(input_dir, output_file, node_filter, edge_filter):
    all_nodes = {}
    all_edges = [] 

    files = glob.glob(os.path.join(input_dir, "**", "*"), recursive=True)
    files = [f for f in files if os.path.isfile(f) and not f.startswith('.')]
    
    print(f"Found {len(files)} files to process in {input_dir}")

    for f in files:
        try:
            with open(f, 'r') as tf:
                header = tf.read(100)
                if 'xml' not in header and 'graphml' not in header:
                    continue
        except:
            continue
            
        print(f"Processing {f}...")
        nodes, edges = parse_graphml_file(f, node_filter, edge_filter)
        
        for n in nodes:
            all_nodes[n['id']] = n
        all_edges.extend(edges)

    # Filter edges where nodes might have been filtered out
    # If we filter out a node, we should probably filter out connected edges too to maintain referential integrity
    valid_node_ids = set(all_nodes.keys())
    final_edges = [e for e in all_edges if e['src'] in valid_node_ids and e['dst'] in valid_node_ids]
    
    filtered_edge_count = len(all_edges) - len(final_edges)
    if filtered_edge_count > 0:
        print(f"Removed {filtered_edge_count} edges because their endpoints were filtered out.")

    data = {
        "nodes": list(all_nodes.values()),
        "edges": final_edges
    }
    
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Converted {len(data['nodes'])} nodes and {len(data['edges'])} edges to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Joern GraphML to JSON with filtering")
    parser.add_argument("input_dir", help="Input directory containing GraphML files")
    parser.add_argument("output_file", help="Output JSON file")
    
    parser.add_argument("--include-nodes", help="Comma-separated list of node types to include", default="")
    parser.add_argument("--exclude-nodes", help="Comma-separated list of node types to exclude", default="")
    parser.add_argument("--include-edges", help="Comma-separated list of edge types to include", default="")
    parser.add_argument("--exclude-edges", help="Comma-separated list of edge types to exclude", default="")
    
    args = parser.parse_args()
    
    n_inc = [x.strip() for x in args.include_nodes.split(',')] if args.include_nodes else []
    n_exc = [x.strip() for x in args.exclude_nodes.split(',')] if args.exclude_nodes else []
    e_inc = [x.strip() for x in args.include_edges.split(',')] if args.include_edges else []
    e_exc = [x.strip() for x in args.exclude_edges.split(',')] if args.exclude_edges else []
    
    node_filter = create_filter(n_inc, n_exc)
    edge_filter = create_filter(e_inc, e_exc)
    
    convert_all(args.input_dir, args.output_file, node_filter, edge_filter)
