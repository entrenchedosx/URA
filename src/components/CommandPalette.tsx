import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  BookMarked,
  CheckSquare,
  Crosshair,
  Database,
  FilePlus2,
  FolderOpen,
  FolderSearch,
  Hash,
  KeyRound,
  Layers,
  LayoutDashboard,
  ListTree,
  MessageSquare,
  PanelLeft,
  PanelRight,
  Plus,
  RotateCcw,
  ScanSearch,
  Search,
  Settings,
  Square,
  Terminal,
  Trash2,
  X,
} from "lucide-react";
import { formatHex, normalizeAddress, parseHex } from "../lib/format";
import { useSession } from "../state/session";
import { useSettings } from "../state/settings";
import { useWorkspace } from "../state/workspace";

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onOpenSettings: () => void;
  onOpenGoTo: () => void;
}

interface PaletteItem {
  id: string;
  label: string;
  detail?: string;
  category: string;
  icon: React.ComponentType<{ className?: string }>;
  run: () => void;
}

function looksLikeAddress(query: string): boolean {
  const trimmed = query.trim();
  return (
    /^@?0x[0-9a-f_]+$/i.test(trimmed) || /^\d{4,}$/.test(trimmed)
  );
}

export function CommandPalette({
  open,
  onClose,
  onOpenSettings,
  onOpenGoTo,
}: CommandPaletteProps) {
  const {
    binary,
    projectPath,
    annotations,
    selection,
    currentFunction,
    openBinaryDialog,
    openProjectDialog,
    newProject,
    closeBinary,
    scanStrings,
    navigate,
    goBack,
    goForward,
    createUserFunction,
    deleteUserFunction,
  } = useSession();
  const { settings, update } = useSettings();
  const { focusView, togglePanel, resetLayout } = useWorkspace();

  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setSelected(0);
      const frame = requestAnimationFrame(() => inputRef.current?.focus());
      return () => cancelAnimationFrame(frame);
    }
  }, [open]);

  const actions = useMemo<PaletteItem[]>(() => {
    const items: PaletteItem[] = [
      {
        id: "open-binary",
        label: "Open binary…",
        detail: "Ctrl+O",
        category: "Binary",
        icon: FolderOpen,
        run: openBinaryDialog,
      },
      {
        id: "open-project",
        label: "Open analysis project…",
        detail: "Ctrl+Shift+O",
        category: "Project",
        icon: FolderSearch,
        run: openProjectDialog,
      },
      {
        id: "new-project",
        label: "New analysis project…",
        detail: "Ctrl+N",
        category: "Project",
        icon: FilePlus2,
        run: newProject,
      },
      {
        id: "go-to",
        label: "Go to address, offset or symbol…",
        detail: "Ctrl+G",
        category: "Navigate",
        icon: Crosshair,
        run: onOpenGoTo,
      },
      {
        id: "history-back",
        label: "Navigate back",
        detail: "Alt+Left",
        category: "Navigate",
        icon: ArrowLeft,
        run: goBack,
      },
      {
        id: "history-forward",
        label: "Navigate forward",
        detail: "Alt+Right",
        category: "Navigate",
        icon: ArrowRight,
        run: goForward,
      },
      {
        id: "view-disassembly",
        label: "Focus Disassembly",
        detail: "Ctrl+1",
        category: "View",
        icon: ListTree,
        run: () => focusView("disassembly"),
      },
      {
        id: "view-hex",
        label: "Focus Hex",
        detail: "Ctrl+2",
        category: "View",
        icon: Hash,
        run: () => focusView("hex"),
      },
      {
        id: "view-strings",
        label: "Focus Strings",
        detail: "Ctrl+3",
        category: "View",
        icon: ScanSearch,
        run: () => focusView("strings"),
      },
      {
        id: "view-overview",
        label: "Focus Overview",
        detail: "Ctrl+4",
        category: "View",
        icon: Layers,
        run: () => focusView("overview"),
      },
      {
        id: "toggle-explorer",
        label: "Toggle Explorer",
        category: "Layout",
        icon: PanelLeft,
        run: () => togglePanel("explorer"),
      },
      {
        id: "toggle-inspector",
        label: "Toggle Inspector",
        category: "Layout",
        icon: PanelRight,
        run: () => togglePanel("inspector"),
      },
      {
        id: "toggle-messages",
        label: "Toggle Messages",
        category: "Layout",
        icon: MessageSquare,
        run: () => togglePanel("messages"),
      },
      {
        id: "reset-layout",
        label: "Reset workspace layout",
        category: "Layout",
        icon: RotateCcw,
        run: resetLayout,
      },
      {
        id: "toggle-bytes",
        label: settings.showBytes
          ? "Hide instruction bytes column"
          : "Show instruction bytes column",
        category: "Settings",
        icon: settings.showBytes ? CheckSquare : Square,
        run: () => update({ showBytes: !settings.showBytes }),
      },
      {
        id: "settings",
        label: "Open settings…",
        detail: "Ctrl+,",
        category: "Settings",
        icon: Settings,
        run: onOpenSettings,
      },
      {
        id: "scan-strings",
        label: "Scan strings (min length 4)",
        category: "String",
        icon: ScanSearch,
        run: () => scanStrings(4, true, true),
      },
    ];
    if (binary) {
      items.push({
        id: "close-binary",
        label: "Close binary",
        category: "Binary",
        icon: X,
        run: closeBinary,
      });
    }
    if (projectPath && selection?.address) {
      items.push({
        id: "define-function",
        label: `Define function at ${normalizeAddress(selection.address) ?? selection.address}`,
        category: "Function",
        icon: Plus,
        run: () => createUserFunction(selection.address as string),
      });
    }
    if (projectPath && currentFunction?.origin === "user") {
      items.push({
        id: "delete-function",
        label: `Delete user-defined function at ${currentFunction.address}`,
        category: "Function",
        icon: Trash2,
        run: () => deleteUserFunction(currentFunction.address),
      });
    }
    if (binary?.info.entryPoint) {
      items.unshift({
        id: "entry-point",
        label: "Go to entry point",
        detail: formatHex(binary.info.entryPoint, 16),
        category: "Navigate",
        icon: Terminal,
        run: () => navigate({ address: binary.info.entryPoint }, "disassembly"),
      });
    }
    if (selection?.address) {
      items.unshift({
        id: "selected-address",
        label: `Go to selected address ${normalizeAddress(selection.address) ?? selection.address}`,
        category: "Navigate",
        icon: Crosshair,
        run: () => navigate({ address: selection.address }, "disassembly"),
      });
    }
    return items;
  }, [
    binary,
    currentFunction?.address,
    currentFunction?.origin,
    projectPath,
    selection,
    settings.showBytes,
    navigate,
    closeBinary,
    createUserFunction,
    deleteUserFunction,
    focusView,
    goBack,
    goForward,
    onOpenGoTo,
    onOpenSettings,
    openBinaryDialog,
    openProjectDialog,
    newProject,
    resetLayout,
    scanStrings,
    togglePanel,
    update,
  ]);

  const items = useMemo<PaletteItem[]>(() => {
    const trimmed = query.trim();
    const needle = trimmed.toLowerCase();
    const results: PaletteItem[] = [];

    if (trimmed && looksLikeAddress(trimmed) && parseHex(trimmed.replace(/^@/, "")) != null) {
      const offsetMode = trimmed.startsWith("@");
      const normalized =
        normalizeAddress(trimmed.replace(/^@/, "")) ?? trimmed.replace(/^@/, "");
      results.push({
        id: "address",
        label: offsetMode
          ? `Go to file offset ${normalized}`
          : `Go to address ${normalized}`,
        detail: offsetMode ? "file offset" : "hex address",
        category: "Address",
        icon: offsetMode ? KeyRound : Crosshair,
        run: () =>
          offsetMode
            ? navigate({ fileOffset: normalized }, "hex")
            : navigate({ address: normalized }, "disassembly"),
      });
    }

    const matchedActions = actions.filter(
      (item) =>
        !needle ||
        item.label.toLowerCase().includes(needle) ||
        item.category.toLowerCase().includes(needle),
    );
    results.push(...matchedActions);

    if (binary && needle) {
      for (const section of binary.sections) {
        if (section.name.toLowerCase().includes(needle)) {
          results.push({
            id: `section-${section.name}-${section.address}`,
            label: section.name,
            detail: formatHex(section.address),
            category: "Section",
            icon: LayoutDashboard,
            run: () =>
              navigate(
                { address: section.address, fileOffset: section.fileOffset },
                section.executable ? "disassembly" : "hex",
              ),
          });
        }
      }

      let symbolMatches = 0;
      for (const symbol of binary.symbols) {
        if (symbolMatches >= 8) break;
        if (!symbol.defined || !symbol.address) continue;
        if (!symbol.name.toLowerCase().includes(needle)) continue;
        symbolMatches += 1;
        results.push({
          id: `symbol-${symbol.name}-${symbol.address}`,
          label: symbol.name,
          detail: formatHex(symbol.address),
          category: "Symbol",
          icon: ListTree,
          run: () => {
            const section = binary.sections.find(
              (candidate) => candidate.name === symbol.section,
            );
            navigate(
              { address: symbol.address },
              section?.executable ? "disassembly" : "hex",
            );
          },
        });
      }

      for (const exportEntry of binary.exports) {
        if (results.length > 24) break;
        if (!exportEntry.name.toLowerCase().includes(needle)) continue;
        results.push({
          id: `export-${exportEntry.name}`,
          label: exportEntry.name,
          detail: formatHex(exportEntry.address),
          category: "Export",
          icon: Database,
          run: () => navigate({ address: exportEntry.address }, "disassembly"),
        });
      }

      for (const annotation of annotations) {
        const label = annotation.label ?? annotation.note;
        if (!label.toLowerCase().includes(needle)) continue;
        results.push({
          id: `annotation-${annotation.id}`,
          label,
          detail: formatHex(annotation.address),
          category: "Annotation",
          icon: BookMarked,
          run: () => navigate({ address: annotation.address }),
        });
      }
    }

    return results.slice(0, 28);
  }, [query, actions, binary, annotations, navigate]);

  useEffect(() => {
    setSelected(0);
  }, [query]);

  useEffect(() => {
    const element = listRef.current?.querySelector<HTMLElement>(
      `[data-index="${selected}"]`,
    );
    element?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  if (!open) return null;

  const runItem = (item: PaletteItem | undefined) => {
    if (!item) return;
    onClose();
    item.run();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-4 pt-[10vh] backdrop-blur-[2px]"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-[600px] overflow-hidden rounded-xl border border-edge-strong bg-obsidian-850 shadow-[0_24px_80px_rgba(0,0,0,0.65)]">
        <div className="flex items-center gap-2 border-b border-edge bg-obsidian-800 px-3">
          <Search className="size-4 shrink-0 text-ink-500" />
          <input
            ref={inputRef}
            className="h-11 flex-1 bg-transparent text-[13px] text-ink-100 placeholder:text-ink-500 focus:outline-none"
            placeholder="Type an address, @file-offset, symbol, section or command…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                event.preventDefault();
                onClose();
              } else if (event.key === "ArrowDown") {
                event.preventDefault();
                setSelected((value) =>
                  items.length === 0 ? 0 : (value + 1) % items.length,
                );
              } else if (event.key === "ArrowUp") {
                event.preventDefault();
                setSelected((value) =>
                  items.length === 0
                    ? 0
                    : (value - 1 + items.length) % items.length,
                );
              } else if (event.key === "Enter") {
                event.preventDefault();
                runItem(items[selected]);
              }
            }}
            spellCheck={false}
          />
          <span className="kbd">Esc</span>
        </div>

        <div ref={listRef} className="max-h-[360px] overflow-auto py-1">
          {items.length === 0 ? (
            <div className="px-4 py-8 text-center text-[12px] text-ink-500">
              No matching commands, symbols or addresses.
            </div>
          ) : (
            items.map((item, index) => {
              const Icon = item.icon;
              const active = index === selected;
              return (
                <button
                  key={item.id}
                  data-index={index}
                  className={`flex w-full items-center gap-2.5 px-3 py-2 text-left transition-colors ${
                    active ? "bg-accent-500/12" : "hover:bg-obsidian-800"
                  }`}
                  onMouseEnter={() => setSelected(index)}
                  onClick={() => runItem(item)}
                >
                  <Icon
                    className={`size-4 shrink-0 ${active ? "text-accent-300" : "text-ink-500"}`}
                  />
                  <span className="min-w-0 flex-1 truncate text-[12.5px] text-ink-200">
                    {item.label}
                  </span>
                  {item.detail && (
                    <span className="shrink-0 font-mono text-[10px] text-ink-500">
                      {item.detail}
                    </span>
                  )}
                  <span className="w-16 shrink-0 text-right text-[9px] uppercase tracking-wider text-ink-600">
                    {item.category}
                  </span>
                </button>
              );
            })
          )}
        </div>

        <div className="flex items-center gap-3 border-t border-edge bg-obsidian-900 px-3 py-1.5 font-mono text-[9.5px] text-ink-500">
          <span>
            <span className="kbd mr-1">↑</span>
            <span className="kbd mr-1">↓</span>
            navigate
          </span>
          <span>
            <span className="kbd mr-1">Enter</span>
            run
          </span>
          <div className="flex-1" />
          <span>0x… address · @0x… file offset</span>
        </div>
      </div>
    </div>
  );
}
