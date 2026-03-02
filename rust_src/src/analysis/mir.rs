use rustc_middle::ty::{self, TyCtxt};
use rustc_middle::mir::{TerminatorKind, StatementKind, Rvalue, Operand, Body, UnwindAction};
use crate::cpg::nodes::{CpgGraph, CpgNode, CallNode, LocalNode, IdentifierNode, LiteralNode, ControlStructureNode};
use crate::analysis::hir::next_id;
use std::collections::HashMap;
use rustc_hir::def_id::DefId;

pub fn analyze_mir<'tcx>(tcx: TyCtxt<'tcx>, graph: &mut CpgGraph, def_to_node_id: &HashMap<DefId, i64>) {
    // 遍历 def_to_node_id 中的所有 DefId，这些是 HIR 阶段识别出的所有函数（包括 Impl 块中的）
    for (&def_id, &method_id) in def_to_node_id.iter() {
        // 确保是函数（或者有关联项）且有 MIR
        if tcx.is_mir_available(def_id) {
            log::info!("Analyzing MIR for: {:?}", tcx.def_path_str(def_id));
            let body = tcx.optimized_mir(def_id);

            // DDG: 跟踪变量的最后定义位置 (Variable Name -> Node ID)
            // 简单起见，我们在处理 Body 时直接维护这个 Map。
            // 注意：跨 Block 的 Def-Use 需要完整的数据流分析，这里先实现 Block 内和基于顺序的简单 DDG。
            let mut last_def: HashMap<String, i64> = HashMap::new();

            // 0. 生成 LOCAL 节点
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
                
                // 将 Local 声明视为初始 Def
                last_def.insert(name, local_id);
            }
            
            // 1. 为每个 BasicBlock 分配一个 ID，并创建对应的 CPG 节点
            let mut bb_to_id = HashMap::new();
            for (bb, data) in body.basic_blocks.iter_enumerated() {
                let bb_node_id = next_id();
                bb_to_id.insert(bb, bb_node_id);

                let code = format!("{:?}", data);
                let is_cleanup = data.is_cleanup;
                
                let block_node = crate::cpg::nodes::BlockNode {
                    id: bb_node_id,
                    code: code.lines().next().unwrap_or("").to_string(),
                    type_full_name: "BasicBlock".to_string(),
                    is_unsafe: false,
                    is_cleanup,
                    line_number: None,
                };
                graph.add_node(CpgNode::BLOCK(block_node));

                // 处理 Block 内的 Statements
                for stmt in &data.statements {
                    if let StatementKind::Assign(assignment) = &stmt.kind {
                        let (place, rvalue) = &**assignment;
                        
                        // 创建 Assignment CALL 节点 (=)
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

                        // LHS: Identifier (这是定义点 Def)
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
                        
                        // RHS: 处理 Use
                        let rhs_id = process_rvalue(rvalue, graph, body, tcx, &last_def);
                        graph.add_edge(assign_id, rhs_id, "AST");
                        graph.add_edge(assign_id, rhs_id, "ARGUMENT");

                        // 更新 Def 记录
                        last_def.insert(lhs_name, lhs_id);
                    }
                }
            }
            
            // 连接 METHOD 到 Entry Block (bb0)
            if let Some(entry_bb_id) = bb_to_id.get(&rustc_middle::mir::BasicBlock::from_u32(0)) {
                graph.add_edge(method_id, *entry_bb_id, "CFG");
            }

            // 2. 遍历 BasicBlocks 构建 CFG 边 (DDG via process_operand called within Terminator processing)
            for (bb, data) in body.basic_blocks.iter_enumerated() {
                let src_id = bb_to_id[&bb];
                let terminator = data.terminator();
                
                // 处理 Terminator
                match &terminator.kind {
                    TerminatorKind::Goto { target } => {
                        if let Some(dst_id) = bb_to_id.get(target) {
                            graph.add_edge(src_id, *dst_id, "CFG");
                        }
                    }
                    TerminatorKind::SwitchInt { targets, discr, .. } => {
                        // Create CONTROL_STRUCTURE node
                        let control_id = next_id();
                        let code = format!("switch({:?})", discr);
                        let type_str = if targets.iter().count() == 1 { "IF" } else { "SWITCH" };

                        let control_node = ControlStructureNode {
                            id: control_id,
                            code: code.clone(),
                            control_structure_type: type_str.to_string(),
                            line_number: None,
                        };
                        graph.add_node(CpgNode::ControlStructure(control_node));
                        graph.add_edge(src_id, control_id, "AST");
                        
                        // DDG for switch condition (Use)
                        let _discr_id = process_operand(discr, graph, body, tcx, &last_def);

                        for (val, target) in targets.iter() {
                            if let Some(dst_id) = bb_to_id.get(&target) {
                                let mut props = serde_json::Map::new();
                                props.insert("condition_value".to_string(), serde_json::Value::String(val.to_string()));
                                graph.add_edge_with_props(src_id, *dst_id, "CFG", props.clone());
                                graph.add_edge_with_props(control_id, *dst_id, "AST", props);
                            }
                        }
                        if let Some(dst_id) = bb_to_id.get(&targets.otherwise()) {
                            let mut props = serde_json::Map::new();
                            props.insert("condition_value".to_string(), serde_json::Value::String("otherwise".to_string()));
                            graph.add_edge_with_props(src_id, *dst_id, "CFG", props.clone());
                            graph.add_edge_with_props(control_id, *dst_id, "AST", props);
                        }
                    }
                    TerminatorKind::Call { func, target, args, unwind, .. } => {
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

                                 // 处理参数 (Uses)
                                 for arg in args {
                                     let arg_id = process_operand(&arg.node, graph, body, tcx, &last_def);
                                     graph.add_edge(call_node_id, arg_id, "AST");
                                     graph.add_edge(call_node_id, arg_id, "ARGUMENT");
                                 }
                                 
                                 call_node_created = Some(call_node_id);
                             }
                        }

                        // 正常控制流
                        if let Some(target_bb) = target {
                            if let Some(dst_id) = bb_to_id.get(target_bb) {
                                if let Some(call_id) = call_node_created {
                                    graph.add_edge(src_id, call_id, "CFG");
                                    graph.add_edge(call_id, *dst_id, "CFG");
                                } else {
                                    graph.add_edge(src_id, *dst_id, "CFG");
                                }
                            }
                        }

                        // 异常控制流 (Unwind)
                        if let UnwindAction::Cleanup(cleanup_bb) = unwind {
                            if let Some(cleanup_id) = bb_to_id.get(cleanup_bb) {
                                graph.add_edge(src_id, *cleanup_id, "CFG_UNWIND");
                            }
                        }
                    }
                    TerminatorKind::Return => {}
                    TerminatorKind::Assert { target, unwind, .. } | TerminatorKind::Drop { target, unwind, .. } => {
                         // 正常控制流
                         if let Some(dst_id) = bb_to_id.get(target) {
                             graph.add_edge(src_id, *dst_id, "CFG");
                         }
                         
                         // 异常控制流 (Unwind)
                         if let UnwindAction::Cleanup(cleanup_bb) = unwind {
                             if let Some(cleanup_id) = bb_to_id.get(cleanup_bb) {
                                 graph.add_edge(src_id, *cleanup_id, "CFG_UNWIND");
                             }
                         }
                    }
                    TerminatorKind::InlineAsm { targets, unwind, .. } => {
                         // InlineAsm uses 'targets' which is Box<[BasicBlock]> (or similar sequence)
                         for target_bb in targets.iter() {
                             if let Some(dst_id) = bb_to_id.get(target_bb) {
                                 graph.add_edge(src_id, *dst_id, "CFG");
                             }
                         }

                         // 异常控制流 (Unwind)
                         if let UnwindAction::Cleanup(cleanup_bb) = unwind {
                             if let Some(cleanup_id) = bb_to_id.get(cleanup_bb) {
                                 graph.add_edge(src_id, *cleanup_id, "CFG_UNWIND");
                             }
                         }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn process_rvalue<'tcx>(rvalue: &Rvalue<'tcx>, graph: &mut CpgGraph, body: &Body<'tcx>, tcx: TyCtxt<'tcx>, last_def: &HashMap<String, i64>) -> i64 {
    match rvalue {
        Rvalue::Use(op) => process_operand(op, graph, body, tcx, last_def),
        Rvalue::BinaryOp(op, operands) => {
            let (lhs, rhs) = &**operands;
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
            let code = format!("&{:?}", place);
            let call_node = CallNode {
                id: call_id,
                code: code.clone(),
                name: "<operator>.addressOf".to_string(),
                method_full_name: "<operator>.addressOf".to_string(),
                line_number: None,
                dispatch_type: "STATIC_DISPATCH".to_string(),
                is_ffi: false,
            };
            graph.add_node(CpgNode::CALL(call_node));

            // Create Identifier for the place being referenced
            let place_id = next_id();
            let place_name = format!("{:?}", place);
            let place_ty = place.ty(&body.local_decls, tcx).ty;
            let place_node = IdentifierNode {
                id: place_id,
                name: place_name.clone(),
                code: place_name.clone(),
                type_full_name: format!("{:?}", place_ty),
                line_number: None,
            };
            graph.add_node(CpgNode::IDENTIFIER(place_node));
            
            // DDG for the referenced variable
            if let Some(def_id) = last_def.get(&place_name) {
                graph.add_edge(*def_id, place_id, "DDG");
            }

            graph.add_edge(call_id, place_id, "AST");
            graph.add_edge(call_id, place_id, "ARGUMENT");
            
            call_id
        }
        Rvalue::Cast(_, op, ty) => {
            let call_id = next_id();
            let code = format!("({:?}) {:?}", ty, op);
            let call_node = CallNode {
                id: call_id,
                code: code.clone(),
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

fn process_operand<'tcx>(op: &Operand<'tcx>, graph: &mut CpgGraph, body: &Body<'tcx>, tcx: TyCtxt<'tcx>, last_def: &HashMap<String, i64>) -> i64 {
    match op {
        Operand::Copy(place) | Operand::Move(place) => {
            let id = next_id();
            let name = format!("{:?}", place);
            let ty = place.ty(&body.local_decls, tcx).ty;
            let node = IdentifierNode {
                id,
                name: name.clone(),
                code: name.clone(),
                type_full_name: format!("{:?}", ty),
                line_number: None,
            };
            graph.add_node(CpgNode::IDENTIFIER(node));
            
            // DDG Edge: Connect from Last Def to this Use
            if let Some(def_id) = last_def.get(&name) {
                graph.add_edge(*def_id, id, "DDG");
            }
            
            id
        }
        Operand::Constant(c) => {
            let id = next_id();
            let code = format!("{:?}", c);
            let ty = c.ty();
            let node = LiteralNode {
                id,
                code: code.clone(),
                type_full_name: format!("{:?}", ty),
                line_number: None,
            };
            graph.add_node(CpgNode::LITERAL(node));
            id
        }
        _ => {
             // Handle other operands (e.g. RuntimeChecks)
             let id = next_id();
             let code = format!("{:?}", op);
             let node = IdentifierNode {
                 id,
                 name: "UNKNOWN_OPERAND".to_string(),
                 code,
                 type_full_name: "UNKNOWN".to_string(),
                 line_number: None,
             };
             graph.add_node(CpgNode::IDENTIFIER(node));
             id
        }
    }
}
