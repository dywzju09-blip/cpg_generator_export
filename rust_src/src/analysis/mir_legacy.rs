use crate::analysis::hir::next_id;
use crate::cpg::nodes::{
    CallNode, ControlStructureNode, CpgGraph, CpgNode, IdentifierNode, LiteralNode, LocalNode,
};
use rustc_hir::def_id::DefId;
use rustc_middle::mir::{Body, Operand, Rvalue, StatementKind, TerminatorKind};
use rustc_middle::ty::{self, TyCtxt};
use std::collections::HashMap;

pub fn analyze_mir<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &mut CpgGraph,
    def_to_node_id: &HashMap<DefId, i64>,
) {
    for (&def_id, &method_id) in def_to_node_id.iter() {
        if !tcx.is_mir_available(def_id) {
            continue;
        }
        log::info!("Analyzing MIR for: {:?}", tcx.def_path_str(def_id));
        let body = tcx.optimized_mir(def_id);
        let mut last_def: HashMap<String, i64> = HashMap::new();

        for (local, decl) in body.local_decls.iter_enumerated() {
            let local_id = next_id();
            let name = format!("{:?}", local);
            let local_node = LocalNode {
                id: local_id,
                name: name.clone(),
                code: name.clone(),
                type_full_name: format!("{:?}", decl.ty),
                line_number: None,
            };
            graph.add_node(CpgNode::LOCAL(local_node));
            graph.add_edge(method_id, local_id, "AST");
            last_def.insert(name, local_id);
        }

        let mut bb_to_id = HashMap::new();
        for (bb, data) in body.basic_blocks().iter_enumerated() {
            let bb_node_id = next_id();
            bb_to_id.insert(bb, bb_node_id);

            let block_node = crate::cpg::nodes::BlockNode {
                id: bb_node_id,
                code: format!("{:?}", data)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string(),
                type_full_name: "BasicBlock".to_string(),
                is_unsafe: false,
                is_cleanup: data.is_cleanup,
                line_number: None,
            };
            graph.add_node(CpgNode::BLOCK(block_node));

            for stmt in &data.statements {
                if let StatementKind::Assign(assignment) = &stmt.kind {
                    let (place, rvalue) = &**assignment;
                    let assign_id = next_id();
                    let assign_node = CallNode {
                        id: assign_id,
                        code: format!("{:?} = {:?}", place, rvalue),
                        name: "<operator>.assignment".to_string(),
                        method_full_name: "<operator>.assignment".to_string(),
                        line_number: None,
                        dispatch_type: "STATIC_DISPATCH".to_string(),
                        is_ffi: false,
                    };
                    graph.add_node(CpgNode::CALL(assign_node));
                    graph.add_edge(bb_node_id, assign_id, "AST");

                    let lhs_id = next_id();
                    let lhs_name = format!("{:?}", place);
                    let lhs_ty = place.ty(&body.local_decls, tcx).ty;
                    let lhs_node = IdentifierNode {
                        id: lhs_id,
                        name: lhs_name.clone(),
                        code: lhs_name.clone(),
                        type_full_name: format!("{:?}", lhs_ty),
                        line_number: None,
                    };
                    graph.add_node(CpgNode::IDENTIFIER(lhs_node));
                    graph.add_edge(assign_id, lhs_id, "AST");
                    graph.add_edge(assign_id, lhs_id, "ARGUMENT");

                    let rhs_id = process_rvalue(rvalue, graph, body, tcx, &last_def);
                    graph.add_edge(assign_id, rhs_id, "AST");
                    graph.add_edge(assign_id, rhs_id, "ARGUMENT");
                    last_def.insert(lhs_name, lhs_id);
                }
            }
        }

        if let Some(entry_bb_id) = bb_to_id.get(&rustc_middle::mir::BasicBlock::from_u32(0)) {
            graph.add_edge(method_id, *entry_bb_id, "CFG");
        }

        for (bb, data) in body.basic_blocks().iter_enumerated() {
            let src_id = bb_to_id[&bb];
            let terminator = data.terminator();
            match &terminator.kind {
                TerminatorKind::Goto { target } => {
                    if let Some(dst_id) = bb_to_id.get(target) {
                        graph.add_edge(src_id, *dst_id, "CFG");
                    }
                }
                TerminatorKind::SwitchInt {
                    discr,
                    values,
                    targets,
                    ..
                } => {
                    let control_id = next_id();
                    let control_node = ControlStructureNode {
                        id: control_id,
                        code: format!("switch({:?})", discr),
                        control_structure_type: if values.len() <= 1 {
                            "IF".to_string()
                        } else {
                            "SWITCH".to_string()
                        },
                        line_number: None,
                    };
                    graph.add_node(CpgNode::ControlStructure(control_node));
                    graph.add_edge(src_id, control_id, "AST");
                    let _ = process_operand(discr, graph, body, tcx, &last_def);

                    for (val, target) in values.iter().zip(targets.iter()) {
                        if let Some(dst_id) = bb_to_id.get(target) {
                            let mut props = serde_json::Map::new();
                            props.insert(
                                "condition_value".to_string(),
                                serde_json::Value::String(val.to_string()),
                            );
                            graph.add_edge_with_props(src_id, *dst_id, "CFG", props.clone());
                            graph.add_edge_with_props(control_id, *dst_id, "AST", props);
                        }
                    }
                    if let Some(otherwise_bb) = targets.last() {
                        if let Some(dst_id) = bb_to_id.get(otherwise_bb) {
                            let mut props = serde_json::Map::new();
                            props.insert(
                                "condition_value".to_string(),
                                serde_json::Value::String("otherwise".to_string()),
                            );
                            graph.add_edge_with_props(src_id, *dst_id, "CFG", props.clone());
                            graph.add_edge_with_props(control_id, *dst_id, "AST", props);
                        }
                    }
                }
                TerminatorKind::Call {
                    func,
                    destination,
                    args,
                    cleanup,
                    ..
                } => {
                    let func_ty = func.ty(body, tcx);
                    let mut call_node_created = None;
                    if let ty::FnDef(func_def_id, _) = func_ty.kind() {
                        let method_name = tcx.item_name(*func_def_id).to_string();
                        let is_ffi = tcx.is_foreign_item(*func_def_id);
                        let target_method_id = def_to_node_id.get(func_def_id);
                        if target_method_id.is_some() || is_ffi {
                            let call_node_id = next_id();
                            let call_node = CallNode {
                                id: call_node_id,
                                code: format!("{:?}", func),
                                name: method_name.clone(),
                                method_full_name: method_name,
                                line_number: None,
                                dispatch_type: "STATIC_DISPATCH".to_string(),
                                is_ffi,
                            };
                            graph.add_node(CpgNode::CALL(call_node));
                            graph.add_edge(src_id, call_node_id, "AST");
                            if let Some(tid) = target_method_id {
                                graph.add_edge(call_node_id, *tid, "CALL");
                                graph.add_edge(call_node_id, *tid, "CFG");
                            }
                            for arg in args {
                                let arg_id = process_operand(arg, graph, body, tcx, &last_def);
                                graph.add_edge(call_node_id, arg_id, "AST");
                                graph.add_edge(call_node_id, arg_id, "ARGUMENT");
                            }
                            call_node_created = Some(call_node_id);
                        }
                    }

                    if let Some((_, target_bb)) = destination {
                        if let Some(dst_id) = bb_to_id.get(target_bb) {
                            if let Some(call_id) = call_node_created {
                                graph.add_edge(src_id, call_id, "CFG");
                                graph.add_edge(call_id, *dst_id, "CFG");
                            } else {
                                graph.add_edge(src_id, *dst_id, "CFG");
                            }
                        }
                    }

                    if let Some(cleanup_bb) = cleanup {
                        if let Some(cleanup_id) = bb_to_id.get(cleanup_bb) {
                            graph.add_edge(src_id, *cleanup_id, "CFG_UNWIND");
                        }
                    }
                }
                TerminatorKind::Assert {
                    target, cleanup, ..
                } => {
                    if let Some(dst_id) = bb_to_id.get(target) {
                        graph.add_edge(src_id, *dst_id, "CFG");
                    }
                    if let Some(cleanup_bb) = cleanup {
                        if let Some(cleanup_id) = bb_to_id.get(cleanup_bb) {
                            graph.add_edge(src_id, *cleanup_id, "CFG_UNWIND");
                        }
                    }
                }
                TerminatorKind::Drop { target, unwind, .. }
                | TerminatorKind::DropAndReplace { target, unwind, .. } => {
                    if let Some(dst_id) = bb_to_id.get(target) {
                        graph.add_edge(src_id, *dst_id, "CFG");
                    }
                    if let Some(cleanup_bb) = unwind {
                        if let Some(cleanup_id) = bb_to_id.get(cleanup_bb) {
                            graph.add_edge(src_id, *cleanup_id, "CFG_UNWIND");
                        }
                    }
                }
                TerminatorKind::InlineAsm { destination, .. } => {
                    if let Some(target_bb) = destination {
                        if let Some(dst_id) = bb_to_id.get(target_bb) {
                            graph.add_edge(src_id, *dst_id, "CFG");
                        }
                    }
                }
                TerminatorKind::FalseEdge {
                    real_target,
                    imaginary_target,
                } => {
                    if let Some(dst_id) = bb_to_id.get(real_target) {
                        graph.add_edge(src_id, *dst_id, "CFG");
                    }
                    if let Some(dst_id) = bb_to_id.get(imaginary_target) {
                        graph.add_edge(src_id, *dst_id, "CFG_FAKE");
                    }
                }
                TerminatorKind::FalseUnwind {
                    real_target,
                    unwind,
                } => {
                    if let Some(dst_id) = bb_to_id.get(real_target) {
                        graph.add_edge(src_id, *dst_id, "CFG");
                    }
                    if let Some(cleanup_bb) = unwind {
                        if let Some(cleanup_id) = bb_to_id.get(cleanup_bb) {
                            graph.add_edge(src_id, *cleanup_id, "CFG_FAKE");
                        }
                    }
                }
                TerminatorKind::Return
                | TerminatorKind::Resume
                | TerminatorKind::Abort
                | TerminatorKind::Unreachable
                | TerminatorKind::Yield { .. }
                | TerminatorKind::GeneratorDrop => {}
            }
        }
    }
}

fn process_rvalue<'tcx>(
    rvalue: &Rvalue<'tcx>,
    graph: &mut CpgGraph,
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    last_def: &HashMap<String, i64>,
) -> i64 {
    match rvalue {
        Rvalue::Use(op) => process_operand(op, graph, body, tcx, last_def),
        Rvalue::BinaryOp(op, lhs, rhs) | Rvalue::CheckedBinaryOp(op, lhs, rhs) => {
            let call_id = next_id();
            let op_name = format!("{:?}", op);
            let call_node = CallNode {
                id: call_id,
                code: op_name.clone(),
                name: op_name.clone(),
                method_full_name: op_name,
                line_number: None,
                dispatch_type: "STATIC_DISPATCH".to_string(),
                is_ffi: false,
            };
            graph.add_node(CpgNode::CALL(call_node));

            let lhs_id = process_operand(lhs, graph, body, tcx, last_def);
            let rhs_id = process_operand(rhs, graph, body, tcx, last_def);
            graph.add_edge(call_id, lhs_id, "AST");
            graph.add_edge(call_id, rhs_id, "AST");
            graph.add_edge(call_id, lhs_id, "ARGUMENT");
            graph.add_edge(call_id, rhs_id, "ARGUMENT");
            call_id
        }
        Rvalue::Ref(_, _, place) => {
            let call_id = next_id();
            let place_name = format!("{:?}", place);
            let place_id = next_id();
            let place_node = IdentifierNode {
                id: place_id,
                name: place_name.clone(),
                code: place_name.clone(),
                type_full_name: format!("{:?}", place.ty(&body.local_decls, tcx).ty),
                line_number: None,
            };
            let call_node = CallNode {
                id: call_id,
                code: format!("&{:?}", place),
                name: "<operator>.addressOf".to_string(),
                method_full_name: "<operator>.addressOf".to_string(),
                line_number: None,
                dispatch_type: "STATIC_DISPATCH".to_string(),
                is_ffi: false,
            };
            graph.add_node(CpgNode::CALL(call_node));
            graph.add_node(CpgNode::IDENTIFIER(place_node));
            if let Some(def_id) = last_def.get(&place_name) {
                graph.add_edge(*def_id, place_id, "DDG");
            }
            graph.add_edge(call_id, place_id, "AST");
            graph.add_edge(call_id, place_id, "ARGUMENT");
            call_id
        }
        Rvalue::Cast(_, op, ty) => {
            let call_id = next_id();
            let call_node = CallNode {
                id: call_id,
                code: format!("({:?}) {:?}", ty, op),
                name: "<operator>.cast".to_string(),
                method_full_name: "<operator>.cast".to_string(),
                line_number: None,
                dispatch_type: "STATIC_DISPATCH".to_string(),
                is_ffi: false,
            };
            graph.add_node(CpgNode::CALL(call_node));
            let arg_id = process_operand(op, graph, body, tcx, last_def);
            graph.add_edge(call_id, arg_id, "AST");
            graph.add_edge(call_id, arg_id, "ARGUMENT");
            call_id
        }
        _ => {
            let id = next_id();
            let node = IdentifierNode {
                id,
                name: "UNKNOWN_RVALUE".to_string(),
                code: format!("{:?}", rvalue),
                type_full_name: "UNKNOWN".to_string(),
                line_number: None,
            };
            graph.add_node(CpgNode::IDENTIFIER(node));
            id
        }
    }
}

fn process_operand<'tcx>(
    op: &Operand<'tcx>,
    graph: &mut CpgGraph,
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    last_def: &HashMap<String, i64>,
) -> i64 {
    match op {
        Operand::Copy(place) | Operand::Move(place) => {
            let id = next_id();
            let name = format!("{:?}", place);
            let node = IdentifierNode {
                id,
                name: name.clone(),
                code: name.clone(),
                type_full_name: format!("{:?}", place.ty(&body.local_decls, tcx).ty),
                line_number: None,
            };
            graph.add_node(CpgNode::IDENTIFIER(node));
            if let Some(def_id) = last_def.get(&name) {
                graph.add_edge(*def_id, id, "DDG");
            }
            id
        }
        Operand::Constant(c) => {
            let id = next_id();
            let node = LiteralNode {
                id,
                code: format!("{:?}", c),
                type_full_name: format!("{:?}", c.literal.ty),
                line_number: None,
            };
            graph.add_node(CpgNode::LITERAL(node));
            id
        }
    }
}
