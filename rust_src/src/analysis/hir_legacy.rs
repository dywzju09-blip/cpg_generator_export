use crate::cpg::nodes::{
    BlockNode, CpgGraph, CpgNode, MemberNode, MethodNode, MethodParameterInNode, MethodReturnNode,
    TypeDeclNode,
};
use rustc_hir::def_id::DefId;
use rustc_hir::{BodyId, ImplItemKind, ItemKind, VariantData};
use rustc_middle::ty::TyCtxt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};

static NODE_ID_COUNTER: AtomicI64 = AtomicI64::new(1);

pub fn next_id() -> i64 {
    NODE_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

fn span_filename<'tcx>(tcx: TyCtxt<'tcx>, span: rustc_span::Span) -> String {
    match tcx.sess.source_map().span_to_filename(span) {
        rustc_span::FileName::Real(name) => name.local_path().display().to_string(),
        other => format!("{:?}", other),
    }
}

pub fn analyze_hir<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &mut CpgGraph,
    def_to_node_id: &mut HashMap<DefId, i64>,
) {
    let hir = tcx.hir();
    for item_id in hir.krate().item.module.item_ids.iter().copied() {
        let item = hir.item(item_id.id);
        let def_id = hir.local_def_id(item.hir_id).to_def_id();
        let filename = span_filename(tcx, item.span);

        match item.kind {
            ItemKind::Fn(ref sig, _, body_id) => {
                process_function(
                    tcx,
                    def_id,
                    sig.decl,
                    body_id,
                    filename,
                    item.span,
                    graph,
                    def_to_node_id,
                );
            }
            ItemKind::Impl { items, .. } => {
                log::info!("Found Impl block: {:?}", tcx.def_path_str(def_id));
                for impl_item_ref in items {
                    let impl_item = hir.impl_item(impl_item_ref.id);
                    let impl_item_def_id = hir.local_def_id(impl_item.hir_id).to_def_id();
                    if let ImplItemKind::Fn(ref sig, body_id) = impl_item.kind {
                        let method_filename = span_filename(tcx, impl_item.span);
                        process_function(
                            tcx,
                            impl_item_def_id,
                            sig.decl,
                            body_id,
                            method_filename,
                            impl_item.span,
                            graph,
                            def_to_node_id,
                        );
                    }
                }
            }
            ItemKind::Struct(ref variant_data, _) => {
                let name = tcx.item_name(def_id).to_string();
                let full_name = tcx.def_path_str(def_id);
                let type_decl_id = next_id();
                def_to_node_id.insert(def_id, type_decl_id);
                let type_decl = TypeDeclNode {
                    id: type_decl_id,
                    name: name.clone(),
                    full_name: full_name.clone(),
                    filename: filename.clone(),
                    code: tcx
                        .sess
                        .source_map()
                        .span_to_snippet(item.span)
                        .unwrap_or_default(),
                };
                graph.add_node(CpgNode::TypeDecl(type_decl));

                if let VariantData::Struct(fields, _) = variant_data {
                    for field in fields.iter() {
                        let member_id = next_id();
                        let member_name = field.ident.as_str().to_string();
                        let member_node = MemberNode {
                            id: member_id,
                            name: member_name.clone(),
                            code: member_name,
                            type_full_name: format!("{:?}", field.ty),
                        };
                        graph.add_node(CpgNode::MEMBER(member_node));
                        graph.add_edge(type_decl_id, member_id, "AST");
                    }
                }
            }
            ItemKind::Enum(ref enum_def, _) => {
                let name = tcx.item_name(def_id).to_string();
                let full_name = tcx.def_path_str(def_id);
                let type_decl_id = next_id();
                def_to_node_id.insert(def_id, type_decl_id);
                let type_decl = TypeDeclNode {
                    id: type_decl_id,
                    name: name.clone(),
                    full_name: full_name.clone(),
                    filename: filename.clone(),
                    code: tcx
                        .sess
                        .source_map()
                        .span_to_snippet(item.span)
                        .unwrap_or_default(),
                };
                graph.add_node(CpgNode::TypeDecl(type_decl));
                for variant in enum_def.variants.iter() {
                    let member_id = next_id();
                    let member_name = variant.ident.as_str().to_string();
                    let member_node = MemberNode {
                        id: member_id,
                        name: member_name.clone(),
                        code: member_name,
                        type_full_name: "Variant".to_string(),
                    };
                    graph.add_node(CpgNode::MEMBER(member_node));
                    graph.add_edge(type_decl_id, member_id, "AST");
                }
            }
            _ => {}
        }
    }
}

fn process_function<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
    decl: &rustc_hir::FnDecl<'tcx>,
    body_id: BodyId,
    filename: String,
    span: rustc_span::Span,
    graph: &mut CpgGraph,
    def_to_node_id: &mut HashMap<DefId, i64>,
) {
    let hir = tcx.hir();
    let name = tcx.item_name(def_id).to_string();
    let full_name = tcx.def_path_str(def_id);
    let method_node_id = next_id();
    def_to_node_id.insert(def_id, method_node_id);

    let method_node = MethodNode {
        id: method_node_id,
        name: name.clone(),
        full_name: full_name.clone(),
        signature: format!("{:?}", decl),
        filename: filename.clone(),
        code: tcx
            .sess
            .source_map()
            .span_to_snippet(span)
            .unwrap_or_default(),
        is_external: false,
        line_number: Some(tcx.sess.source_map().lookup_char_pos(span.lo()).line),
    };
    graph.add_node(CpgNode::METHOD(method_node));

    let body = hir.body(body_id);
    for (idx, param) in body.params.iter().enumerate() {
        let param_id = next_id();
        let param_name = tcx
            .sess
            .source_map()
            .span_to_snippet(param.pat.span)
            .unwrap_or_else(|_| format!("param_{}", idx));
        let param_type = if idx < decl.inputs.len() {
            format!("{:?}", decl.inputs[idx])
        } else {
            "UNKNOWN".to_string()
        };
        let param_node = MethodParameterInNode {
            id: param_id,
            name: param_name.clone(),
            code: param_name,
            type_full_name: param_type,
            order: idx as i32,
            line_number: Some(tcx.sess.source_map().lookup_char_pos(param.span.lo()).line),
        };
        graph.add_node(CpgNode::MethodParameterIn(param_node));
        graph.add_edge(method_node_id, param_id, "AST");
    }

    let return_id = next_id();
    let return_node = MethodReturnNode {
        id: return_id,
        type_full_name: format!("{:?}", decl.output),
        code: "RET".to_string(),
        line_number: None,
    };
    graph.add_node(CpgNode::MethodReturn(return_node));
    graph.add_edge(method_node_id, return_id, "AST");

    process_body(tcx, body_id, method_node_id, graph);
}

fn process_body<'tcx>(tcx: TyCtxt<'tcx>, body_id: BodyId, parent_id: i64, graph: &mut CpgGraph) {
    let body = tcx.hir().body(body_id);
    let is_unsafe = if let rustc_hir::ExprKind::Block(block, _) = body.value.kind {
        matches!(block.rules, rustc_hir::BlockCheckMode::UnsafeBlock(_))
    } else {
        false
    };

    let block_id = next_id();
    let block_node = BlockNode {
        id: block_id,
        code: "{ ... }".to_string(),
        type_full_name: "void".to_string(),
        is_unsafe,
        is_cleanup: false,
        line_number: None,
    };
    graph.add_node(CpgNode::BLOCK(block_node));
    graph.add_edge(parent_id, block_id, "AST");
}
