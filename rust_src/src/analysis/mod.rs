use rustc_middle::ty::TyCtxt;
use crate::cpg::nodes::CpgGraph;
use std::collections::HashMap;
use rustc_hir::def_id::DefId;

pub mod hir;
pub mod mir;

pub fn run_analysis<'tcx>(tcx: TyCtxt<'tcx>, graph: &mut CpgGraph) {
    let mut def_to_node_id = HashMap::new();

    log::info!("Starting HIR analysis...");
    hir::analyze_hir(tcx, graph, &mut def_to_node_id);
    
    log::info!("Starting MIR analysis...");
    mir::analyze_mir(tcx, graph, &def_to_node_id);
}
