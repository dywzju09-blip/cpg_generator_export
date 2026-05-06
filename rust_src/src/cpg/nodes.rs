use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub enum CpgNode {
    METHOD(MethodNode),
    MethodParameterIn(MethodParameterInNode),
    BLOCK(BlockNode),
    CALL(CallNode),
    LOCAL(LocalNode),
    ControlStructure(ControlStructureNode),
    RETURN(ReturnNode),
    MethodReturn(MethodReturnNode),
    IDENTIFIER(IdentifierNode),
    TypeDecl(TypeDeclNode),
    MEMBER(MemberNode),
    LITERAL(LiteralNode),
    UNKNOWN(UnknownNode),
}

#[derive(Debug, Clone)]
pub struct MethodReturnNode {
    pub id: i64,
    pub type_full_name: String,
    pub code: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct IdentifierNode {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub type_full_name: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct TypeDeclNode {
    pub id: i64,
    pub name: String,
    pub full_name: String,
    pub filename: String,
    pub code: String,
}

#[derive(Debug, Clone)]
pub struct MemberNode {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub type_full_name: String,
}

#[derive(Debug, Clone)]
pub struct MethodNode {
    pub id: i64,
    pub name: String,
    pub full_name: String,
    pub signature: String,
    pub filename: String,
    pub code: String,
    pub is_external: bool,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct MethodParameterInNode {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub type_full_name: String,
    pub order: i32,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct BlockNode {
    pub id: i64,
    pub code: String,
    pub type_full_name: String,
    pub is_unsafe: bool,
    pub is_cleanup: bool,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct CallNode {
    pub id: i64,
    pub code: String,
    pub name: String,
    pub method_full_name: String,
    pub line_number: Option<usize>,
    pub dispatch_type: String,
    pub is_ffi: bool,
}

#[derive(Debug, Clone)]
pub struct LocalNode {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub type_full_name: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ControlStructureNode {
    pub id: i64,
    pub code: String,
    pub control_structure_type: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ReturnNode {
    pub id: i64,
    pub code: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct LiteralNode {
    pub id: i64,
    pub code: String,
    pub type_full_name: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct UnknownNode {
    pub id: i64,
    pub code: String,
    pub parser_type_name: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct CpgEdge {
    pub src: i64,
    pub dst: i64,
    pub label: String,
    pub properties: Map<String, Value>,
}

#[derive(Debug, Clone)]
pub struct CpgGraph {
    pub nodes: Vec<CpgNode>,
    pub edges: Vec<CpgEdge>,
}

fn insert_string(map: &mut Map<String, Value>, key: &str, value: &str) {
    map.insert(key.to_string(), Value::String(value.to_string()));
}

fn insert_bool(map: &mut Map<String, Value>, key: &str, value: bool) {
    map.insert(key.to_string(), Value::Bool(value));
}

fn insert_i64(map: &mut Map<String, Value>, key: &str, value: i64) {
    map.insert(key.to_string(), Value::from(value));
}

fn insert_i32(map: &mut Map<String, Value>, key: &str, value: i32) {
    map.insert(key.to_string(), Value::from(value));
}

fn insert_line_number(map: &mut Map<String, Value>, value: Option<usize>) {
    let rendered = match value {
        Some(line) => Value::from(line as i64),
        None => Value::Null,
    };
    map.insert("line_number".to_string(), rendered);
}

impl CpgNode {
    pub fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        match self {
            CpgNode::METHOD(node) => {
                insert_string(&mut map, "label", "METHOD");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "name", &node.name);
                insert_string(&mut map, "full_name", &node.full_name);
                insert_string(&mut map, "signature", &node.signature);
                insert_string(&mut map, "filename", &node.filename);
                insert_string(&mut map, "code", &node.code);
                insert_bool(&mut map, "is_external", node.is_external);
                insert_line_number(&mut map, node.line_number);
            }
            CpgNode::MethodParameterIn(node) => {
                insert_string(&mut map, "label", "METHOD_PARAMETER_IN");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "name", &node.name);
                insert_string(&mut map, "code", &node.code);
                insert_string(&mut map, "type_full_name", &node.type_full_name);
                insert_i32(&mut map, "order", node.order);
                insert_line_number(&mut map, node.line_number);
            }
            CpgNode::BLOCK(node) => {
                insert_string(&mut map, "label", "BLOCK");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "code", &node.code);
                insert_string(&mut map, "type_full_name", &node.type_full_name);
                insert_bool(&mut map, "is_unsafe", node.is_unsafe);
                insert_bool(&mut map, "is_cleanup", node.is_cleanup);
                insert_line_number(&mut map, node.line_number);
            }
            CpgNode::CALL(node) => {
                insert_string(&mut map, "label", "CALL");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "code", &node.code);
                insert_string(&mut map, "name", &node.name);
                insert_string(&mut map, "method_full_name", &node.method_full_name);
                insert_line_number(&mut map, node.line_number);
                insert_string(&mut map, "dispatch_type", &node.dispatch_type);
                insert_bool(&mut map, "is_ffi", node.is_ffi);
            }
            CpgNode::LOCAL(node) => {
                insert_string(&mut map, "label", "LOCAL");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "name", &node.name);
                insert_string(&mut map, "code", &node.code);
                insert_string(&mut map, "type_full_name", &node.type_full_name);
                insert_line_number(&mut map, node.line_number);
            }
            CpgNode::ControlStructure(node) => {
                insert_string(&mut map, "label", "CONTROL_STRUCTURE");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "code", &node.code);
                insert_string(
                    &mut map,
                    "control_structure_type",
                    &node.control_structure_type,
                );
                insert_line_number(&mut map, node.line_number);
            }
            CpgNode::RETURN(node) => {
                insert_string(&mut map, "label", "RETURN");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "code", &node.code);
                insert_line_number(&mut map, node.line_number);
            }
            CpgNode::MethodReturn(node) => {
                insert_string(&mut map, "label", "METHOD_RETURN");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "type_full_name", &node.type_full_name);
                insert_string(&mut map, "code", &node.code);
                insert_line_number(&mut map, node.line_number);
            }
            CpgNode::IDENTIFIER(node) => {
                insert_string(&mut map, "label", "IDENTIFIER");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "name", &node.name);
                insert_string(&mut map, "code", &node.code);
                insert_string(&mut map, "type_full_name", &node.type_full_name);
                insert_line_number(&mut map, node.line_number);
            }
            CpgNode::TypeDecl(node) => {
                insert_string(&mut map, "label", "TYPE_DECL");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "name", &node.name);
                insert_string(&mut map, "full_name", &node.full_name);
                insert_string(&mut map, "filename", &node.filename);
                insert_string(&mut map, "code", &node.code);
            }
            CpgNode::MEMBER(node) => {
                insert_string(&mut map, "label", "MEMBER");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "name", &node.name);
                insert_string(&mut map, "code", &node.code);
                insert_string(&mut map, "type_full_name", &node.type_full_name);
            }
            CpgNode::LITERAL(node) => {
                insert_string(&mut map, "label", "LITERAL");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "code", &node.code);
                insert_string(&mut map, "type_full_name", &node.type_full_name);
                insert_line_number(&mut map, node.line_number);
            }
            CpgNode::UNKNOWN(node) => {
                insert_string(&mut map, "label", "UNKNOWN");
                insert_i64(&mut map, "id", node.id);
                insert_string(&mut map, "code", &node.code);
                insert_string(&mut map, "parser_type_name", &node.parser_type_name);
                insert_line_number(&mut map, node.line_number);
            }
        }
        Value::Object(map)
    }
}

impl CpgEdge {
    pub fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        insert_i64(&mut map, "src", self.src);
        insert_i64(&mut map, "dst", self.dst);
        insert_string(&mut map, "label", &self.label);
        map.insert(
            "properties".to_string(),
            Value::Object(self.properties.clone()),
        );
        Value::Object(map)
    }
}

impl CpgGraph {
    pub fn new() -> Self {
        CpgGraph {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: CpgNode) {
        self.nodes.push(node);
    }

    pub fn add_edge(&mut self, src: i64, dst: i64, label: &str) {
        self.edges.push(CpgEdge {
            src,
            dst,
            label: label.to_string(),
            properties: Map::new(),
        });
    }

    pub fn add_edge_with_props(
        &mut self,
        src: i64,
        dst: i64,
        label: &str,
        props: Map<String, Value>,
    ) {
        self.edges.push(CpgEdge {
            src,
            dst,
            label: label.to_string(),
            properties: props,
        });
    }

    pub fn to_json_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "nodes".to_string(),
            Value::Array(self.nodes.iter().map(CpgNode::to_json_value).collect()),
        );
        map.insert(
            "edges".to_string(),
            Value::Array(self.edges.iter().map(CpgEdge::to_json_value).collect()),
        );
        Value::Object(map)
    }

    pub fn write_pretty_json<W: std::io::Write>(&self, writer: W) -> serde_json::Result<()> {
        serde_json::to_writer_pretty(writer, &self.to_json_value())
    }
}
