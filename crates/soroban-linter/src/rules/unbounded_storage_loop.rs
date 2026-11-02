use syn::visit::{self, Visit};
use syn::{Expr, ExprForLoop, ExprLoop, ExprMethodCall, ExprWhile, Macro};

use super::{FileContext, Rule, RuleInfo};
use crate::analysis::{
    line_col, local_callee, loop_bound, macro_exprs, storage_call, Bindings, FnFacts,
};
use crate::finding::{Finding, Severity};

pub struct UnboundedStorageLoop;

static INFO: RuleInfo = RuleInfo {
    id: "SG003",
    name: "unbounded-storage-loop",
    default_severity: Severity::Warning,
    summary: "Loop accesses storage an unbounded number of times or more often than the per-transaction ledger-entry limit",
    help: "Every distinct ledger entry a transaction touches counts against the network's per-transaction \
           read/write entry limits. Bound the loop (paginate with `start`/`limit` arguments, cap batch \
           sizes with a constant) or move per-item state out of the loop.",
};

/// Iterator adapters whose closure runs once per element.
const ITER_ADAPTERS: &[&str] = &[
    "for_each",
    "try_for_each",
    "map",
    "filter",
    "filter_map",
    "flat_map",
    "fold",
    "any",
    "all",
    "find",
    "position",
];

impl Rule for UnboundedStorageLoop {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        for (f, facts) in &cx.fns {
            let mut finder = LoopFinder {
                cx,
                bindings: &facts.bindings,
                caller: facts,
                out: &mut *out,
            };
            finder.visit_block(f.block);
        }
    }
}

/// Upper bound on ledger-entry accesses for a piece of code.
#[derive(Debug, Default, Clone, Copy)]
struct Cost {
    /// Ledger-entry accesses (reads and writes); bounded by the footprint limit.
    entries: u128,
    /// Ledger-entry writes; bounded by the write-entry limit.
    writes: u128,
    unbounded: bool,
}

impl Cost {
    fn is_zero(&self) -> bool {
        self.entries == 0 && !self.unbounded
    }
}

/// Counts storage accesses, multiplying through loops with a known bound.
struct CostCounter<'c> {
    cx: &'c FileContext<'c>,
    bindings: &'c Bindings,
    /// The function being analysed, for resolving calls.
    caller: &'c FnFacts,
    cost: Cost,
}

impl<'c> CostCounter<'c> {
    fn new(cx: &'c FileContext<'c>, bindings: &'c Bindings, caller: &'c FnFacts) -> Self {
        CostCounter {
            cx,
            bindings,
            caller,
            cost: Cost::default(),
        }
    }

    fn sub(&self) -> CostCounter<'c> {
        CostCounter::new(self.cx, self.bindings, self.caller)
    }

    /// Adds the cost of a loop body that runs `bound` times (`None` = unknown).
    fn add_loop(&mut self, bound: Option<u128>, body: Cost) {
        if body.is_zero() {
            return;
        }
        // Unknown bound: count the body once and mark the whole thing unbounded.
        let n = bound.unwrap_or(1);
        self.cost.entries = self
            .cost
            .entries
            .saturating_add(n.saturating_mul(body.entries));
        self.cost.writes = self
            .cost
            .writes
            .saturating_add(n.saturating_mul(body.writes));
        self.cost.unbounded |= body.unbounded || bound.is_none();
    }

    fn closure_body(m: &ExprMethodCall) -> Option<&Expr> {
        if !ITER_ADAPTERS.contains(&m.method.to_string().as_str()) {
            return None;
        }
        m.args.iter().find_map(|a| match a {
            Expr::Closure(c) => Some(&*c.body),
            _ => None,
        })
    }
}

impl<'ast> Visit<'ast> for CostCounter<'_> {
    fn visit_expr_method_call(&mut self, m: &'ast ExprMethodCall) {
        if let Some(call) = storage_call(m, self.bindings) {
            self.cost.entries += 1;
            if call.op.is_mutation() {
                self.cost.writes += 1;
            }
        }
        if let Some(body) = Self::closure_body(m) {
            let mut inner = self.sub();
            inner.visit_expr(body);
            self.visit_expr(&m.receiver);
            let bound = loop_bound(&m.receiver, &self.cx.index.consts);
            self.add_loop(bound, inner.cost);
            return;
        }
        visit::visit_expr_method_call(self, m);
    }

    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if let Some(name) = local_callee(c) {
            let effects = self.cx.index.effects_of(self.caller, &name);
            if effects.touches_storage {
                self.cost.entries += 1;
            }
            if effects.mutates_storage {
                self.cost.writes += 1;
            }
        }
        visit::visit_expr_call(self, c);
    }

    fn visit_expr_for_loop(&mut self, l: &'ast ExprForLoop) {
        self.visit_expr(&l.expr);
        let mut inner = self.sub();
        inner.visit_block(&l.body);
        self.add_loop(loop_bound(&l.expr, &self.cx.index.consts), inner.cost);
    }

    fn visit_expr_while(&mut self, w: &'ast ExprWhile) {
        let mut inner = self.sub();
        inner.visit_expr(&w.cond);
        inner.visit_block(&w.body);
        self.add_loop(None, inner.cost);
    }

    fn visit_expr_loop(&mut self, l: &'ast ExprLoop) {
        let mut inner = self.sub();
        inner.visit_block(&l.body);
        self.add_loop(None, inner.cost);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        for e in macro_exprs(mac) {
            Visit::visit_expr(self, &e);
        }
    }
}

/// Finds outermost loops and reports those that are too expensive.
struct LoopFinder<'c, 'o> {
    cx: &'c FileContext<'c>,
    bindings: &'c Bindings,
    /// The function being analysed, for resolving calls.
    caller: &'c FnFacts,
    out: &'o mut Vec<Finding>,
}

impl LoopFinder<'_, '_> {
    fn report(&mut self, at: (usize, usize), what: &str, cost: Cost) {
        let max_fp = self.cx.config.max_footprint_entries;
        let max_w = self.cx.config.max_write_entries;
        let (severity, message) = if cost.unbounded {
            (
                Severity::Warning,
                format!(
                    "{what} accesses contract storage on every iteration, but its iteration count is \
                     not statically bounded; large inputs or state will exceed the per-transaction \
                     limits ({max_fp} footprint entries, {max_w} written entries) and make the call fail"
                ),
            )
        } else if cost.entries > max_fp {
            (
                Severity::Error,
                format!(
                    "{what} may access up to {} ledger entries, exceeding the per-transaction \
                     footprint limit of {max_fp}",
                    cost.entries
                ),
            )
        } else if cost.writes > max_w {
            (
                Severity::Error,
                format!(
                    "{what} may write up to {} ledger entries, exceeding the per-transaction \
                     write limit of {max_w}",
                    cost.writes
                ),
            )
        } else {
            return;
        };
        self.out.push(self.cx.finding(&INFO, severity, at, message));
    }
}

impl<'ast> Visit<'ast> for LoopFinder<'_, '_> {
    fn visit_expr_for_loop(&mut self, l: &'ast ExprForLoop) {
        let mut c = CostCounter::new(self.cx, self.bindings, self.caller);
        c.visit_expr_for_loop(l);
        self.report(line_col(l.for_token.span), "`for` loop", c.cost);
    }

    fn visit_expr_while(&mut self, w: &'ast ExprWhile) {
        let mut c = CostCounter::new(self.cx, self.bindings, self.caller);
        c.visit_expr_while(w);
        self.report(line_col(w.while_token.span), "`while` loop", c.cost);
    }

    fn visit_expr_loop(&mut self, l: &'ast ExprLoop) {
        let mut c = CostCounter::new(self.cx, self.bindings, self.caller);
        c.visit_expr_loop(l);
        self.report(line_col(l.loop_token.span), "`loop`", c.cost);
    }

    fn visit_expr_method_call(&mut self, m: &'ast ExprMethodCall) {
        if CostCounter::closure_body(m).is_some() {
            let mut c = CostCounter::new(self.cx, self.bindings, self.caller);
            c.visit_expr_method_call(m);
            let what = format!("`.{}()` iterator closure", m.method);
            self.report(line_col(m.method.span()), &what, c.cost);
            return;
        }
        visit::visit_expr_method_call(self, m);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        for e in macro_exprs(mac) {
            Visit::visit_expr(self, &e);
        }
    }
}
