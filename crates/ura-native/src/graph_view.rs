use crate::{
    app::{Action, Panel, Workspace},
    design::{GRAPH_HEADER, GRAPH_LINE},
    graph::GraphLayout,
};
use eframe::egui::{self, Align2, FontId, Sense, Stroke, StrokeKind};

fn extent(graph: &GraphLayout) -> egui::Vec2 {
    egui::vec2(
        graph
            .nodes
            .iter()
            .map(|n| n.x + n.width)
            .fold(1.0, f32::max),
        graph
            .nodes
            .iter()
            .map(|n| n.y + n.height)
            .fold(1.0, f32::max),
    )
}

impl Workspace {
    pub(crate) fn graph_view(&mut self, ui: &mut egui::Ui) {
        self.ensure_graph();
        let Some(function) = self.function().map(|f| f.address).or(self.graph_function) else {
            ui.label("Select an analyzed function to view its control flow.");
            return;
        };
        let mut fit = false;
        ui.horizontal(|ui| {
            if let Some(f) = self.function() {
                ui.colored_label(self.colors().accent, self.name(f));
            }
            if ui.small_button("Fit").clicked() {
                fit = true;
            }
            if ui.small_button("1:1").clicked() {
                self.graph_zoom = 1.0;
                self.graph_pan = egui::vec2(20.0, 15.0);
            }
            ui.add(
                egui::Slider::new(&mut self.graph_zoom, 0.001..=2.5)
                    .show_value(false)
                    .text("Zoom"),
            );
        });
        let Some(graph) = self.graph.get(&function) else {
            ui.label("Preparing graph…");
            return;
        };
        let facts = &graph.flow;
        if !facts.unresolved_indirect.is_empty()
            || !facts.tail_calls.is_empty()
            || facts.thunk_candidate
        {
            ui.colored_label(self.colors().gold,format!("{} unresolved indirect transfers · {} guarded table candidates · {} tail-call candidates{}",facts.unresolved_indirect.len(),graph.table_candidates,facts.tail_calls.len(),if facts.thunk_candidate {" · thunk candidate"} else {""}));
        }
        if graph.total_blocks > graph.nodes.len() || graph.nodes.iter().any(|n| n.omitted > 0) {
            ui.colored_label(
                self.colors().gold,
                format!(
                    "{} / {} blocks; blocks show up to {} instructions",
                    graph.nodes.len(),
                    graph.total_blocks,
                    crate::graph::LINE_CAP
                ),
            );
        }
        let Some(analysis) = self.analysis.clone() else {
            return;
        };
        let (rect, response) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
        let font_scale = self.settings.graph_font_size / 11.0;
        let size = extent(graph);
        if fit {
            self.graph_zoom = ((rect.width() - 40.0) / (size.x * font_scale))
                .min((rect.height() - 30.0) / (size.y * font_scale))
                .clamp(0.001, 2.5);
            self.graph_pan = egui::vec2(
                (rect.width() - size.x * font_scale * self.graph_zoom) * 0.5,
                15.0,
            );
        }
        if response.dragged() {
            self.graph_pan += response.drag_delta();
        }
        if response.hovered() {
            let scroll = ui.input(|i| i.smooth_scroll_delta.y);
            if scroll != 0.0 {
                let old = self.graph_zoom;
                self.graph_zoom = (old * (scroll * 0.002).exp()).clamp(0.001, 2.5);
                if let Some(pointer) = response.hover_pos() {
                    let relative = pointer - rect.min;
                    self.graph_pan =
                        relative - (relative - self.graph_pan) * (self.graph_zoom / old);
                }
            }
        }
        let zoom = self.graph_zoom * font_scale;
        let origin = rect.min + self.graph_pan;
        let transform = |x: f32, y: f32| origin + egui::vec2(x, y) * zoom;
        let painter = ui.painter().with_clip_rect(rect);
        let p = self.colors();
        painter.rect_filled(rect, 0.0, p.canvas);
        for edge in &graph.edges {
            let a = &graph.nodes[edge.source];
            let b = &graph.nodes[edge.target];
            let branch = match edge.kind {
                ura_core::EdgeKind::Taken => -8.0,
                ura_core::EdgeKind::FallThrough => 8.0,
                _ => 0.0,
            };
            let start = transform(a.x + a.width * 0.5 + branch, a.y + a.height);
            let end = transform(b.x + b.width * 0.5, b.y);
            let color = match edge.kind {
                ura_core::EdgeKind::Taken => p.taken,
                ura_core::EdgeKind::FallThrough => p.fallthrough,
                _ => p.accent,
            };
            let points = if b.y > a.y {
                let middle = start.y + (end.y - start.y) * 0.5;
                vec![
                    start,
                    egui::pos2(start.x, middle),
                    egui::pos2(end.x, middle),
                    end,
                ]
            } else {
                let side = transform(
                    a.x.max(b.x) + a.width.max(b.width) + 14.0 + (edge.source % 3) as f32 * 6.0,
                    0.0,
                )
                .x;
                vec![
                    start,
                    start + egui::vec2(0.0, 12.0 * zoom),
                    egui::pos2(side, start.y + 12.0 * zoom),
                    egui::pos2(side, end.y - 12.0 * zoom),
                    end - egui::vec2(0.0, 12.0 * zoom),
                    end,
                ]
            };
            if egui::Rect::from_points(&points)
                .expand(5.0)
                .intersects(rect)
            {
                painter.add(egui::Shape::line(points, Stroke::new(1.0, color)));
                painter.add(egui::Shape::convex_polygon(
                    vec![
                        end,
                        end + egui::vec2(-3.0, -6.0),
                        end + egui::vec2(3.0, -6.0),
                    ],
                    color,
                    Stroke::NONE,
                ));
            }
        }
        let mut jump = None;
        for node in &graph.nodes {
            let r = egui::Rect::from_min_size(
                transform(node.x, node.y),
                egui::vec2(node.width, node.height) * zoom,
            );
            if !r.intersects(rect) {
                continue;
            }
            let selected = analysis
                .block_containing(self.location.address.unwrap_or(0))
                .is_some_and(|b| b.address == node.address);
            painter.rect_filled(r, 0.0, p.node);
            painter.rect_stroke(
                r,
                0.0,
                Stroke::new(1.0, if selected { p.accent } else { p.border }),
                StrokeKind::Inside,
            );
            let paint = painter.with_clip_rect(rect.intersect(r));
            paint.rect_filled(
                egui::Rect::from_min_size(r.min, egui::vec2(r.width(), 21.0 * zoom)),
                0.0,
                p.panel,
            );
            paint.text(
                r.min + egui::vec2(6.0, 3.0) * zoom,
                Align2::LEFT_TOP,
                format!("loc_{:X}:", node.address),
                FontId::monospace(11.0 * zoom),
                p.accent,
            );
            for (row, address) in node.lines.iter().enumerate() {
                let Some(i) = analysis.instructions.get(address) else {
                    continue;
                };
                let pos = r.min + egui::vec2(7.0, GRAPH_HEADER + row as f32 * GRAPH_LINE) * zoom;
                if self.location.address == Some(*address) {
                    paint.rect_filled(
                        egui::Rect::from_min_size(
                            pos - egui::vec2(3.0, 0.0),
                            egui::vec2(node.width - 8.0, GRAPH_LINE) * zoom,
                        ),
                        0.0,
                        p.selected,
                    );
                }
                paint.text(
                    pos,
                    Align2::LEFT_TOP,
                    &i.mnemonic,
                    FontId::monospace(11.0 * zoom),
                    crate::views::instruction_color(i.flow.name(), i.invalid, p),
                );
                let operands =
                    paint.layout_job(crate::views::assembly_job(&i.operands, 11.0 * zoom, p));
                paint.galley(pos + egui::vec2(65.0 * zoom, 0.0), operands, p.text);
            }
            if node.omitted > 0 {
                paint.text(
                    r.left_bottom() + egui::vec2(7.0, -16.0) * zoom,
                    Align2::LEFT_TOP,
                    format!("… {} more instructions", node.omitted),
                    FontId::monospace(11.0 * zoom),
                    p.muted,
                );
            }
            if (response.clicked() || response.double_clicked())
                && let Some(pos) = response.interact_pointer_pos()
                && r.contains(pos)
            {
                let row = (((pos.y - r.top()) / zoom - GRAPH_HEADER) / GRAPH_LINE)
                    .floor()
                    .max(0.0) as usize;
                jump = Some(if pos.y < r.top() + GRAPH_HEADER * zoom {
                    node.address
                } else {
                    node.lines.get(row).copied().unwrap_or(node.address)
                });
            }
        }
        if let Some(address) = jump {
            self.navigate_address(address);
            if response.double_clicked() {
                self.actions.push(Action::Show(Panel::Disassembly));
            }
        }
        response.context_menu(|ui| {
            if ui.button("Open selection in disassembly").clicked() {
                self.actions.push(Action::Show(Panel::Disassembly));
                ui.close();
            }
            if let Some(address) = self.location.address {
                self.address_menu(ui, address);
            }
        });
    }

    pub(crate) fn graph_overview(&mut self, ui: &mut egui::Ui) {
        self.ensure_graph();
        let Some(graph) = self.graph_function.and_then(|f| self.graph.get(&f)) else {
            ui.label("No function graph");
            return;
        };
        let total_blocks = graph.total_blocks;
        let (rect, response) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
        let size = extent(graph) + egui::vec2(20.0, 20.0);
        let scale = ((rect.width() - 12.0) / size.x)
            .min((rect.height() - 12.0) / size.y)
            .max(0.001);
        let origin = rect.min + egui::vec2((rect.width() - size.x * scale) * 0.5, 6.0);
        let painter = ui.painter().with_clip_rect(rect);
        let p = self.colors();
        painter.rect_filled(rect, 0.0, p.bg);
        for edge in &graph.edges {
            let a = &graph.nodes[edge.source];
            let b = &graph.nodes[edge.target];
            painter.line_segment(
                [
                    origin + egui::vec2(a.x + a.width * 0.5, a.y + a.height) * scale,
                    origin + egui::vec2(b.x + b.width * 0.5, b.y) * scale,
                ],
                Stroke::new(1.0, p.border),
            );
        }
        for n in &graph.nodes {
            let r = egui::Rect::from_min_size(
                origin + egui::vec2(n.x, n.y) * scale,
                egui::vec2(n.width, n.height) * scale,
            );
            let selected = self
                .analysis
                .as_ref()
                .and_then(|a| a.block_containing(self.location.address.unwrap_or(0)))
                .is_some_and(|b| b.address == n.address);
            painter.rect_filled(r, 0.0, if selected { p.selected } else { p.panel });
            painter.rect_stroke(
                r,
                0.0,
                Stroke::new(1.0, if selected { p.accent } else { p.border }),
                StrokeKind::Inside,
            );
        }
        if (response.clicked() || response.dragged())
            && let Some(pos) = response.interact_pointer_pos()
        {
            let point = (pos - origin) / scale;
            if let Some(node) = graph.nodes.iter().min_by(|a, b| {
                (egui::vec2(a.x + a.width * 0.5, a.y + a.height * 0.5) - point)
                    .length_sq()
                    .total_cmp(
                        &(egui::vec2(b.x + b.width * 0.5, b.y + b.height * 0.5) - point)
                            .length_sq(),
                    )
            }) {
                let address = node.address;
                self.graph_pan = egui::vec2(20.0, 15.0)
                    - egui::vec2(node.x, node.y)
                        * self.graph_zoom
                        * (self.settings.graph_font_size / 11.0);
                self.navigate_address(address);
                self.actions.push(Action::Show(Panel::Graph));
            }
        }
        response.on_hover_text(format!("{total_blocks} blocks · click to navigate"));
    }
}
