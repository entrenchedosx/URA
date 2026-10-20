//! Shared native workspace metrics and semantic colours.
use eframe::egui::{self, Color32, FontId, Stroke};
use serde::{Deserialize, Serialize};

pub const TAB_HEIGHT: f32 = 22.0;
pub const STATUS_HEIGHT: f32 = 22.0;
pub const GRAPH_LINE: f32 = 16.0;
pub const GRAPH_HEADER: f32 = 25.0;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    #[default]
    Classic,
    Dark,
}

#[derive(Clone, Copy)]
pub struct Palette {
    pub bg: Color32,
    pub panel: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub gold: Color32,
    pub selected: Color32,
    pub canvas: Color32,
    pub node: Color32,
    pub register: Color32,
    pub branch: Color32,
    pub error: Color32,
    pub taken: Color32,
    pub fallthrough: Color32,
}

impl Theme {
    pub fn palette(self) -> Palette {
        let rgb = Color32::from_rgb;
        match self {
            Self::Classic => Palette {
                bg: rgb(255, 255, 255),
                panel: rgb(239, 239, 239),
                border: rgb(166, 171, 177),
                text: rgb(26, 28, 32),
                muted: rgb(89, 98, 112),
                accent: rgb(0, 38, 145),
                gold: rgb(137, 75, 0),
                selected: rgb(211, 230, 253),
                canvas: rgb(231, 249, 252),
                node: rgb(255, 255, 255),
                register: rgb(0, 98, 71),
                branch: rgb(105, 24, 139),
                error: rgb(177, 25, 28),
                taken: rgb(25, 143, 66),
                fallthrough: rgb(191, 53, 53),
            },
            Self::Dark => Palette {
                bg: rgb(30, 33, 39),
                panel: rgb(40, 43, 49),
                border: rgb(78, 84, 94),
                text: rgb(219, 222, 228),
                muted: rgb(155, 164, 178),
                accent: rgb(142, 185, 236),
                gold: rgb(218, 183, 124),
                selected: rgb(49, 70, 94),
                canvas: rgb(25, 30, 36),
                node: rgb(38, 42, 49),
                register: rgb(149, 194, 164),
                branch: rgb(193, 166, 217),
                error: rgb(238, 139, 139),
                taken: rgb(113, 193, 139),
                fallthrough: rgb(224, 139, 133),
            },
        }
    }
}

pub fn apply(ctx: &egui::Context, settings: &crate::app::Settings) {
    let p = settings.theme.palette();
    let theme = if settings.theme == Theme::Classic {
        egui::Theme::Light
    } else {
        egui::Theme::Dark
    };
    let mut style = egui::Style::default();
    let mut v = if theme == egui::Theme::Light {
        egui::Visuals::light()
    } else {
        egui::Visuals::dark()
    };
    v.panel_fill = p.panel;
    v.window_fill = p.panel;
    v.extreme_bg_color = p.bg;
    v.faint_bg_color = p.panel;
    v.override_text_color = Some(p.text);
    v.selection.bg_fill = p.selected;
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.window_corner_radius = egui::CornerRadius::ZERO;
    for widget in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        widget.corner_radius = egui::CornerRadius::ZERO;
        widget.bg_stroke = Stroke::new(1.0, p.border);
        widget.fg_stroke = Stroke::new(1.0, p.text);
    }
    v.widgets.inactive.weak_bg_fill = p.panel;
    v.widgets.hovered.weak_bg_fill = p.selected;
    v.widgets.active.weak_bg_fill = p.selected;
    style.visuals = v;
    style.spacing.item_spacing = egui::vec2(4.0, 2.0);
    style.spacing.button_padding = egui::vec2(5.0, 2.0);
    style.spacing.interact_size = egui::vec2(22.0, 18.0);
    style.spacing.scroll.bar_width = 10.0;
    for text in [egui::TextStyle::Body, egui::TextStyle::Button] {
        style
            .text_styles
            .insert(text, FontId::proportional(settings.ui_font_size));
    }
    style.text_styles.insert(
        egui::TextStyle::Small,
        FontId::proportional((settings.ui_font_size - 1.0).max(10.0)),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        FontId::monospace(settings.font_size),
    );
    ctx.set_theme(theme);
    ctx.set_style_of(theme, style);
}
