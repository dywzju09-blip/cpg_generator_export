#![feature(rustc_private)]

extern crate rustc_data_structures;
extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

pub mod analysis;
pub mod cpg;

use crate::cpg::nodes::CpgGraph;
use rustc_interface::interface;
#[cfg(not(legacy_rustc_private_api))]
use rustc_middle::ty::TyCtxt;
use std::sync::{Arc, Mutex};

pub struct CpgCompilerCallbacks {
    pub graph: Arc<Mutex<CpgGraph>>,
}

impl CpgCompilerCallbacks {
    pub fn new(graph: Arc<Mutex<CpgGraph>>) -> Self {
        CpgCompilerCallbacks { graph }
    }
}

impl rustc_driver::Callbacks for CpgCompilerCallbacks {
    #[cfg(not(legacy_rustc_private_api))]
    fn after_analysis<'tcx>(
        &mut self,
        _compiler: &interface::Compiler,
        tcx: TyCtxt<'tcx>,
    ) -> rustc_driver::Compilation {
        let mut graph = self.graph.lock().unwrap();
        analysis::run_analysis(tcx, &mut graph);
        rustc_driver::Compilation::Continue
    }

    #[cfg(legacy_rustc_private_api)]
    fn after_analysis<'tcx>(
        &mut self,
        _compiler: &interface::Compiler,
        queries: &'tcx rustc_interface::Queries<'tcx>,
    ) -> rustc_driver::Compilation {
        if let Ok(global_ctxt) = queries.global_ctxt() {
            global_ctxt.peek_mut().enter(|tcx| {
                let mut graph = self.graph.lock().unwrap();
                analysis::run_analysis(tcx, &mut graph);
            });
        }
        rustc_driver::Compilation::Continue
    }
}
