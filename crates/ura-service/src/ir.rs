use crate::error::ServiceResult;
use crate::{Service, ServiceError, RESPONSE_SCHEMA_VERSION};
use serde::Serialize;
use std::sync::Arc;
use ura_core::ir::{self, Address};

const MAX_CACHED_FUNCTIONS: usize = 8;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IrPage {
    pub schema_version: u32,
    pub ir_version: u32,
    pub handle: String,
    pub binary_hash: String,
    pub function: Address,
    pub address_width: u16,
    pub representation: String,
    pub analysis_partial: bool,
    pub analysis_options: crate::dto::AnalysisOptionsView,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub rows: Vec<ir::inspect::Row>,
    pub variables: std::collections::BTreeMap<usize, ir::Variable>,
    pub unsupported_instructions: usize,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DominatorRow {
    pub block: Address,
    pub immediate_dominator: Address,
    pub frontier: Vec<Address>,
    pub children: Vec<Address>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DominatorPage {
    pub schema_version: u32,
    pub ir_version: u32,
    pub function: Address,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub rows: Vec<DominatorRow>,
    pub unreachable: Vec<Address>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsPage {
    pub schema_version: u32,
    pub ir_version: u32,
    pub function: Address,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub diagnostics: Vec<ir::Diagnostic>,
    pub constant_values: usize,
    pub dead_definitions: usize,
    pub proven_branches: std::collections::BTreeMap<Address, bool>,
    pub unresolved_indirect_transfers: usize,
    pub tail_call_candidates: usize,
    pub jump_table_candidates: usize,
}

impl Service {
    fn lifted(&mut self, handle: &str, address: &str) -> ServiceResult<Arc<ir::inspect::Bundle>> {
        let session = self
            .sessions
            .get_mut(handle)
            .ok_or_else(|| ServiceError::UnknownHandle(handle.into()))?;
        let analysis = session
            .analysis
            .as_ref()
            .ok_or(ServiceError::AnalysisRequired)?;
        let address = ura_core::parse_address(address)?;
        let function = analysis
            .function_containing(address)
            .ok_or_else(|| ServiceError::FunctionNotFound(ura_core::format_address(address)))?
            .address;
        if let Some(cached) = session.ir_cache.get(&function).cloned() {
            session.ir_cache_order.retain(|key| *key != function);
            session.ir_cache_order.push_back(function);
            return Ok(cached);
        }
        let bundle = Arc::new(
            ir::inspect::analyze(&session.binary, analysis, function, &())
                .map_err(ServiceError::InvalidArgument)?,
        );
        // Bounded LRU cache; it is invalidated on every core reanalysis.
        while session.ir_cache.len() >= MAX_CACHED_FUNCTIONS {
            let Some(oldest) = session.ir_cache_order.pop_front() else {
                session.ir_cache.clear();
                break;
            };
            session.ir_cache.remove(&oldest);
        }
        session.ir_cache.insert(function, bundle.clone());
        session.ir_cache_order.push_back(function);
        Ok(bundle)
    }
    pub fn ir(
        &mut self,
        handle: &str,
        address: &str,
        ssa: bool,
        offset: usize,
        limit: usize,
    ) -> ServiceResult<IrPage> {
        if !(1..=500).contains(&limit) {
            return Err(ServiceError::LimitExceeded(
                "IR page limit must be 1..500".into(),
            ));
        }
        let bundle = self.lifted(handle, address)?;
        let total = bundle.row_count(ssa);
        let offset = offset.min(total);
        let rows = bundle.rows(ssa, offset, limit);
        let variables = bundle.row_variables(&rows);
        let report = &self.sessions[handle].analysis.as_ref().unwrap().report;
        Ok(IrPage {
            schema_version: RESPONSE_SCHEMA_VERSION,
            ir_version: ir::IR_VERSION,
            handle: handle.into(),
            binary_hash: self.sessions[handle].info.sha256.clone(),
            function: bundle.raw.entry,
            address_width: bundle.raw.address_width,
            representation: if ssa { "ssa" } else { "raw" }.into(),
            analysis_partial: report.cancelled || report.truncated,
            analysis_options: crate::dto::AnalysisOptionsView::from(
                self.sessions[handle].analysis_options.as_ref().unwrap(),
            ),
            total,
            offset,
            limit,
            rows,
            variables,
            unsupported_instructions: bundle.raw.diagnostics.len(),
        })
    }
    pub fn dominators(
        &mut self,
        handle: &str,
        address: &str,
        offset: usize,
        limit: usize,
    ) -> ServiceResult<DominatorPage> {
        if !(1..=200).contains(&limit) {
            return Err(ServiceError::LimitExceeded(
                "dominator page limit must be 1..200".into(),
            ));
        }
        let bundle = self.lifted(handle, address)?;
        let dom = &bundle.ssa.dominators;
        let offset = offset.min(dom.immediate.len());
        let rows = dom
            .immediate
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(b, p)| DominatorRow {
                block: *b,
                immediate_dominator: *p,
                frontier: dom.frontiers[b].clone(),
                children: dom.children[b].clone(),
            })
            .collect();
        Ok(DominatorPage {
            schema_version: RESPONSE_SCHEMA_VERSION,
            ir_version: ir::IR_VERSION,
            function: bundle.raw.entry,
            total: dom.immediate.len(),
            offset,
            limit,
            rows,
            unreachable: dom.unreachable.clone(),
        })
    }
    pub fn analysis_diagnostics(
        &mut self,
        handle: &str,
        address: &str,
        offset: usize,
        limit: usize,
    ) -> ServiceResult<DiagnosticsPage> {
        if !(1..=500).contains(&limit) {
            return Err(ServiceError::LimitExceeded(
                "diagnostic page limit must be 1..500".into(),
            ));
        }
        let bundle = self.lifted(handle, address)?;
        let analysis = self.sessions[handle].analysis.as_ref().unwrap();
        let function = analysis.function_by_start(bundle.raw.entry.0).unwrap();
        let flow = analysis.flow_facts(function);
        let mut diagnostics = bundle.raw.diagnostics.clone();
        diagnostics.extend(analysis.report.diagnostics.iter().filter_map(|d| {
            let source = ura_core::parse_address(d.address.as_deref()?).ok()?;
            analysis
                .function_containing(source)
                .filter(|f| f.address == function.address)
                .map(|_| ir::Diagnostic {
                    source: Address(source),
                    message: d.message.clone(),
                })
        }));
        let total = diagnostics.len();
        let offset = offset.min(total);
        Ok(DiagnosticsPage {
            schema_version: RESPONSE_SCHEMA_VERSION,
            ir_version: ir::IR_VERSION,
            function: bundle.raw.entry,
            total,
            offset,
            limit,
            diagnostics: diagnostics.into_iter().skip(offset).take(limit).collect(),
            constant_values: bundle.dataflow.constants.len(),
            dead_definitions: bundle.dataflow.dead_definitions.len(),
            proven_branches: bundle.dataflow.proven_branches.clone(),
            unresolved_indirect_transfers: flow.unresolved_indirect.len(),
            tail_call_candidates: flow.tail_calls.len(),
            jump_table_candidates: function
                .blocks
                .iter()
                .filter_map(|b| analysis.blocks.get(b))
                .filter(|b| {
                    b.instructions
                        .last()
                        .is_some_and(|i| analysis.jump_tables.contains_key(i))
                })
                .count(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn analyzed() -> (Service, String) {
        let mut service = Service::new(crate::PathPolicy::allow_all(), false);
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ura64.exe");
        let handle = service.open_binary(&path, None).unwrap().handle;
        service.analyze(&handle, &Default::default()).unwrap();
        (service, handle)
    }
    #[test]
    fn cache_reuses_verified_bundle_and_invalidates_after_configuration_changes() {
        let (mut service, h) = analyzed();
        let first = service.lifted(&h, "140001020").unwrap();
        let again = service.lifted(&h, "140001027").unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        service.ir(&h, "140001020", true, 0, 10).unwrap();
        assert_eq!(service.sessions[&h].ir_cache.len(), 1);
        service
            .analyze(
                &h,
                &ura_core::AnalysisOptions {
                    follow_calls: false,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(service.sessions[&h].ir_cache.is_empty());
        assert_eq!(
            service
                .ir(&h, "140001020", false, 0, 10)
                .err()
                .unwrap()
                .code(),
            "function_not_found"
        );
        service.analyze(&h, &Default::default()).unwrap();
        let rebuilt = service.lifted(&h, "140001020").unwrap();
        assert!(!Arc::ptr_eq(&first, &rebuilt));
    }
    #[test]
    fn ir_pages_match_core_and_resolve_exact_typed_variable_ids() {
        let (mut service, h) = analyzed();
        let bundle = service.lifted(&h, "140001020").unwrap();
        for ssa in [false, true] {
            let page = service.ir(&h, "140001020", ssa, 4, 7).unwrap();
            assert_eq!(page.rows.len(), 7);
            assert_eq!(page.ir_version, 1);
            assert!(!page.analysis_partial);
            assert_eq!(
                serde_json::to_value(&page.rows).unwrap(),
                serde_json::to_value(bundle.rows(ssa, 4, 7)).unwrap()
            );
            assert!(!page.variables.is_empty());
            assert_eq!(
                service
                    .ir(&h, "140001020", ssa, usize::MAX, 7)
                    .unwrap()
                    .rows
                    .len(),
                0
            );
        }
        assert_eq!(
            service
                .ir(&h, "140001020", false, 0, 501)
                .err()
                .unwrap()
                .code(),
            "limit_exceeded"
        );
    }
}
