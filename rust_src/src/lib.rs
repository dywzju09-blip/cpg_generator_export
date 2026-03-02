#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_hir;
extern crate rustc_span;
extern crate rustc_session;
extern crate rustc_data_structures;

pub mod cpg;
pub mod analysis;

use std::sync::{Arc, Mutex};
use rustc_interface::interface;
use rustc_middle::ty::TyCtxt;
use crate::cpg::nodes::CpgGraph;

pub struct CpgCompilerCallbacks {
    pub graph: Arc<Mutex<CpgGraph>>,
}

impl CpgCompilerCallbacks {
    pub fn new(graph: Arc<Mutex<CpgGraph>>) -> Self {
        CpgCompilerCallbacks {
            graph,
        }
    }
}

impl rustc_driver::Callbacks for CpgCompilerCallbacks {
    fn after_analysis<'tcx>(
        &mut self,
        _compiler: &interface::Compiler,
        tcx: TyCtxt<'tcx>,
    ) -> rustc_driver::Compilation {
        let mut graph = self.graph.lock().unwrap();
        analysis::run_analysis(tcx, &mut graph);
        rustc_driver::Compilation::Continue
    }
}
