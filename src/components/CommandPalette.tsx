import { useEffect, useMemo, useRef, useState } from "react";
import {
  BookMarked,
  Crosshair,
  Database,
  FilePlus2,
  FolderOpen,
  FolderSearch,
  Hash,
  Layers,
  ListTree,
  ScanSearch,
  Search,
  Terminal,
} from "lucide-react";
import type {
  Annotation,
  BinaryOpenResult,
  NavigateFn,
  ViewKind,
} from "../lib/types";
import { formatHex, normalizeAddress, parseHex } from "../lib/format";

interface CommandPaletteProps {
  open: boolean;
  binary: BinaryOpenResult | null;
  annotations: Annotation[];
  onClose: () => void;
  onOpenBinary: () => void;
  onNewProject: () => void;
  onOpenProject: () => void;
  onNavigate: NavigateFn;
  onSwitchView: (view: ViewKind) => void;
  onScanStrings: () => void;
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
  return /^0x[0-9a-f_]+$/i.test(trimmed) || /^\d{4,}$/.test(trimmed);
}

export function CommandPalette({
  open,
  binary,
  annotations,
  onClose,
  onOpenBinary,
  onNewProject,
  onOpenProject,
  onNavigate,
  onSwitchView,
  onScanStrings,
}: CommandPaletteProps) {
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
        run: onOpenBinary,
      },
      {
        id: "open-project",
        label: "Open analysis project…",
        detail: "Ctrl+Shift+O",
        category: "Project",
        icon: FolderSearch,
        run: onOpenProject,
      },
      {
        id: "new-project",
        label: "New analysis project…",
        detail: "Ctrl+N",
        category: "Project",
        icon: FilePlus2,
        run: onNewProject,
      },
      {
        id: "view-disassembly",
        label: "Go to Disassembly view",
        detail: "Ctrl+1",
        category: "View",
        icon: ListTree,
        run: () => onSwitchView("disassembly"),
      },
      {
        id: "view-hex",
        label: "Go to Hex view",
        detail: "Ctrl+2",
        category: "View",
        icon: Hash,
        run: () => onSwitchView("hex"),
      },
      {
        id: "view-strings",
        label: "Go to Strings view",
        detail: "Ctrl+3",
        category: "View",
        icon: ScanSearch,
        run: () => onSwitchView("strings"),
      },
      {
        id: "view-overview",
        label: "Go to Overview",
        detail: "Ctrl+4",
        category: "View",
        icon: Layers,
        run: () => onSwitchView("overview"),
      },
      {
        id: "scan-strings",
        label: "Scan strings (min length 4)",
        category: "String",
        icon: ScanSearch,
        run: onScanStrings,
      },
    ];
    if (binary?.info.entryPoint) {
      items.unshift({
        id: "entry-point",
        label: "Go to entry point",
        detail: formatHex(binary.info.entryPoint, 16),
        category: "Navigate",
        icon: Terminal,
        run: () => onNavigate({ address: binary.info.entryPoint }, "disassembly"),
      });
    }
    return items;
  }, [
    binary,
    onNavigate,
    onNewProject,
    onOpenBinary,
    onOpenProject,
    onScanStrings,
    onSwitchView,
  ]);

  const items = useMemo<PaletteItem[]>(() => {
    const trimmed = query.trim();
    const needle = trimmed.toLowerCase();
    const results: PaletteItem[] = [];

    if (trimmed && looksLikeAddress(trimmed) && parseHex(trimmed) != null) {
      const normalized = normalizeAddress(trimmed)!;
      results.push({
        id: "address",
        label: `Go to address ${normalized}`,
        detail: "hex address",
        category: "Address",
        icon: Crosshair,
        run: () => onNavigate({ address: normalized }, "disassembly"),
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
            icon: Layers,
            run: () =>
              onNavigate(
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
            onNavigate(
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
          run: () => onNavigate({ address: exportEntry.address }, "disassembly"),
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
          run: () => onNavigate({ address: annotation.address }),
        });
      }
    }

    return results.slice(0, 28);
  }, [query, actions, binary, annotations, onNavigate]);

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
            placeholder="Type an address, symbol, section or command…"
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
            jump
          </span>
          <div className="flex-1" />
          <span>Addresses accept hex, e.g. 0x140001000</span>
        </div>
      </div>
    </div>
  );
}
