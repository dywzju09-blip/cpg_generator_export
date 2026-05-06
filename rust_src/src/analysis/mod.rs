use crate::cpg::nodes::CpgGraph;
use rustc_middle::ty::TyCtxt;
use std::collections::HashMap;

#[cfg(legacy_rustc_private_api)]
#[path = "hir_legacy.rs"]
pub mod hir;
#[cfg(not(legacy_rustc_private_api))]
pub mod hir;
#[cfg(legacy_rustc_private_api)]
#[path = "mir_legacy.rs"]
pub mod mir;
#[cfg(not(legacy_rustc_private_api))]
pub mod mir;

pub fn run_analysis<'tcx>(tcx: TyCtxt<'tcx>, graph: &mut CpgGraph) {
    let mut def_to_node_id = HashMap::new();

    log::info!("Starting HIR analysis...");
    hir::analyze_hir(tcx, graph, &mut def_to_node_id);

    log::info!("Starting MIR analysis...");
    mir::analyze_mir(tcx, graph, &def_to_node_id);
}
