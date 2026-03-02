use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "label")]
pub enum CpgNode {
    METHOD(MethodNode),
    #[serde(rename = "METHOD_PARAMETER_IN")]
    MethodParameterIn(MethodParameterInNode),
    BLOCK(BlockNode),
    CALL(CallNode),
    LOCAL(LocalNode),
    #[serde(rename = "CONTROL_STRUCTURE")]
    ControlStructure(ControlStructureNode),
    RETURN(ReturnNode),
    #[serde(rename = "METHOD_RETURN")]
    MethodReturn(MethodReturnNode),
    IDENTIFIER(IdentifierNode),
    #[serde(rename = "TYPE_DECL")]
    TypeDecl(TypeDeclNode),
    MEMBER(MemberNode),
    LITERAL(LiteralNode),
    UNKNOWN(UnknownNode),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MethodReturnNode {
    pub id: i64,
    pub type_full_name: String,
    pub code: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdentifierNode {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub type_full_name: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TypeDeclNode {
    pub id: i64,
    pub name: String,
    pub full_name: String,
    pub filename: String,
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MemberNode {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub type_full_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MethodParameterInNode {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub type_full_name: String,
    pub order: i32,
    pub line_number: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockNode {
    pub id: i64,
    pub code: String,
    pub type_full_name: String,
    pub is_unsafe: bool, // Custom property for Rust
    pub is_cleanup: bool, // New property: Is this a cleanup/unwind block?
    pub line_number: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CallNode {
    pub id: i64,
    pub code: String,
    pub name: String,
    pub method_full_name: String,
    pub line_number: Option<usize>,
    pub dispatch_type: String, // STATIC_DISPATCH, DYNAMIC_DISPATCH
    pub is_ffi: bool, // Custom property for Rust
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LocalNode {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub type_full_name: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlStructureNode {
    pub id: i64,
    pub code: String,
    pub control_structure_type: String, // IF, WHILE, MATCH, etc.
    pub line_number: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReturnNode {
    pub id: i64,
    pub code: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LiteralNode {
    pub id: i64,
    pub code: String,
    pub type_full_name: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UnknownNode {
    pub id: i64,
    pub code: String,
    pub parser_type_name: String,
    pub line_number: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CpgEdge {
    pub src: i64,
    pub dst: i64,
    pub label: String, // AST, CFG, REACHING_DEF, CALL, REF, etc.
    pub properties: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CpgGraph {
    pub nodes: Vec<CpgNode>,
    pub edges: Vec<CpgEdge>,
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
            properties: serde_json::Map::new(),
        });
    }

    pub fn add_edge_with_props(&mut self, src: i64, dst: i64, label: &str, props: serde_json::Map<String, serde_json::Value>) {
        self.edges.push(CpgEdge {
            src,
            dst,
            label: label.to_string(),
            properties: props,
        });
    }
}
