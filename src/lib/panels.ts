import type { ViewKind } from "./types";

export type ToolPanelId =
  | "explorer"
  | "inspector"
  | "messages"
  | "cfg"
  | "xrefs";
export type WorkspacePanelId = ViewKind | ToolPanelId;

export const VIEW_PANEL_IDS: ViewKind[] = [
  "disassembly",
  "hex",
  "strings",
  "overview",
];

export const WORKSPACE_PANEL_TITLES: Record<WorkspacePanelId, string> = {
  explorer: "Explorer",
  disassembly: "Disassembly",
  hex: "Hex",
  strings: "Strings",
  overview: "Overview",
  inspector: "Inspector",
  messages: "Messages",
  cfg: "Control Flow",
  xrefs: "Xrefs",
};

export function isViewPanel(id: string): id is ViewKind {
  return (VIEW_PANEL_IDS as string[]).includes(id);
}
