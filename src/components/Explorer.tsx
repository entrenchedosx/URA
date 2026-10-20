import { useMemo, useState } from "react";
import {
  BookMarked,
  Fingerprint,
  Layers,
  PackageOpen,
  Search,
  Tags,
} from "lucide-react";
import type {
  Annotation,
  BinaryOpenResult,
  NavigateFn,
  Selection,
} from "../lib/types";
import { formatHex, formatSize, normalizeAddress } from "../lib/format";
import { VirtualList } from "./VirtualList";

type ExplorerTab = "sections" | "symbols" | "imports" | "exports";

interface ExplorerProps {
  binary: BinaryOpenResult;
  annotations: Annotation[];
  selection: Selection | null;
  onNavigate: NavigateFn;
}

const tabs: Array<{ id: ExplorerTab; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: "sections", label: "Sections", icon: Layers },
  { id: "symbols", label: "Symbols", icon: Tags },
  { id: "imports", label: "Imports", icon: PackageOpen },
  { id: "exports", label: "Exports", icon: Fingerprint },
];

export function Explorer({
  binary,
  annotations,
  selection,
  onNavigate,
}: ExplorerProps) {
  const [tab, setTab] = useState<ExplorerTab>("sections");
  const [filter, setFilter] = useState("");

  const annotated = useMemo(() => {
    const map = new Map<string, Annotation>();
    for (const annotation of annotations) {
      const address = normalizeAddress(annotation.address);
      if (address) map.set(address, annotation);
    }
    return map;
  }, [annotations]);

  const symbols = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return binary.symbols;
    return binary.symbols.filter(
      (symbol) =>
        symbol.name.toLowerCase().includes(needle) ||
        (symbol.section ?? "").toLowerCase().includes(needle) ||
        (symbol.address ?? "").toLowerCase().includes(needle),
    );
  }, [binary.symbols, filter]);

  const imports = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return binary.imports;
    return binary.imports.filter(
      (entry) =>
        entry.name.toLowerCase().includes(needle) ||
        (entry.library ?? "").toLowerCase().includes(needle),
    );
  }, [binary.imports, filter]);

  const exports = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return binary.exports;
    return binary.exports.filter(
      (entry) =>
        entry.name.toLowerCase().includes(needle) ||
        entry.address.toLowerCase().includes(needle),
    );
  }, [binary.exports, filter]);

  const showFilter = tab !== "sections";

  return (
    <aside className="flex w-[264px] shrink-0 flex-col border-r border-edge bg-obsidian-850">
      <div className="panel-header">
        <span className="flex items-center gap-1.5">
          <Layers className="size-3.5" />
          Explorer
        </span>
        <span className="font-mono text-[10px] normal-case tracking-normal text-ink-500">
          {binary.info.format}
        </span>
      </div>

      <div className="grid shrink-0 grid-cols-4 border-b border-edge">
        {tabs.map((entry) => {
          const Icon = entry.icon;
          const active = tab === entry.id;
          return (
            <button
              key={entry.id}
              className={`flex h-8 items-center justify-center gap-1 border-b-2 text-[10.5px] font-medium transition-colors ${
                active
                  ? "border-accent-500 bg-obsidian-800 text-accent-300"
                  : "border-transparent text-ink-500 hover:bg-obsidian-800/60 hover:text-ink-300"
              }`}
              onClick={() => setTab(entry.id)}
              title={entry.label}
            >
              <Icon className="size-3.5" />
              <span className="hidden xl:inline">{entry.label}</span>
            </button>
          );
        })}
      </div>

      {showFilter && (
        <div className="shrink-0 border-b border-edge p-1.5">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-ink-500" />
            <input
              className="input h-7 pl-7 text-[11px]"
              placeholder={`Filter ${tab}…`}
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              spellCheck={false}
            />
          </div>
        </div>
      )}

      <div className="flex min-h-0 flex-1 flex-col">
        {tab === "sections" && (
          <div className="overflow-auto py-1">
            {binary.sections.map((section) => {
              const active = selection?.address != null
                ? (() => {
                    try {
                      const start = BigInt(section.address);
                      const addr = BigInt(selection.address!);
                      return (
                        addr >= start &&
                        addr < start + BigInt(section.size)
                      );
                    } catch {
                      return false;
                    }
                  })()
                : false;
              return (
                <button
                  key={`${section.name}-${section.address}`}
                  className={`flex w-full items-center gap-2 px-2.5 py-1.5 text-left transition-colors ${
                    active ? "bg-accent-500/10" : "hover:bg-obsidian-750/70"
                  }`}
                  onClick={() =>
                    onNavigate(
                      { address: section.address, fileOffset: section.fileOffset },
                      section.executable ? "disassembly" : "hex",
                    )
                  }
                  title={`${section.name} — ${formatSize(section.size)}`}
                >
                  <span
                    className={`h-5 w-0.5 shrink-0 rounded-full ${
                      section.executable
                        ? "bg-accent-500"
                        : section.writable
                          ? "bg-amber-500/70"
                          : "bg-obsidian-600"
                    }`}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-[11.5px] text-ink-200">
                      {section.name}
                    </span>
                    <span className="block font-mono text-[9.5px] text-ink-500">
                      {formatHex(section.address)} · {section.permissions}
                    </span>
                  </span>
                  <span className="shrink-0 font-mono text-[9.5px] text-ink-500">
                    {formatSize(section.size)}
                  </span>
                </button>
              );
            })}
          </div>
        )}

        {tab === "symbols" && (
          <VirtualList
            className="min-h-0 flex-1"
            count={symbols.length}
            estimateSize={27}
            renderRow={(index) => {
              const symbol = symbols[index];
              const address = normalizeAddress(symbol.address);
              const annotation = address ? annotated.get(address) : undefined;
              const active = address != null && selection?.address === address;
              const clickable = Boolean(symbol.defined && symbol.address);
              return (
                <button
                  className={`flex h-[27px] w-full items-center gap-1.5 px-2.5 text-left transition-colors ${
                    active ? "bg-accent-500/10" : "hover:bg-obsidian-750/70"
                  } ${clickable ? "" : "cursor-default opacity-60"}`}
                  disabled={!clickable}
                  onClick={() =>
                    onNavigate(
                      { address: symbol.address },
                      binary.sections.find(
                        (section) => section.name === symbol.section,
                      )?.executable
                        ? "disassembly"
                        : "hex",
                    )
                  }
                  title={`${symbol.name}${symbol.address ? ` — ${symbol.address}` : ""} (${symbol.kind})`}
                >
                  {annotation ? (
                    <BookMarked className="size-3 shrink-0 text-amber-400" />
                  ) : (
                    <span
                      className={`size-1 shrink-0 rounded-full ${
                        symbol.kind === "text"
                          ? "bg-accent-500/80"
                          : symbol.kind === "data"
                            ? "bg-emerald-500/70"
                            : "bg-obsidian-600"
                      }`}
                    />
                  )}
                  <span
                    className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink-300"
                    title={symbol.name}
                  >
                    {symbol.name}
                  </span>
                  <span className="shrink-0 font-mono text-[9.5px] text-ink-500">
                    {address ? formatHex(address) : "undef"}
                  </span>
                </button>
              );
            }}
          />
        )}

        {tab === "imports" && (
          <VirtualList
            className="min-h-0 flex-1"
            count={imports.length}
            estimateSize={27}
            renderRow={(index) => {
              const entry = imports[index];
              return (
                <div className="flex h-[27px] items-center gap-2 px-2.5">
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-[11px] text-ink-200">
                      {entry.name}
                    </span>
                    <span className="block truncate text-[9px] text-ink-500">
                      {entry.library ?? "unknown library"}
                    </span>
                  </span>
                </div>
              );
            }}
          />
        )}

        {tab === "exports" && (
          <VirtualList
            className="min-h-0 flex-1"
            count={exports.length}
            estimateSize={27}
            renderRow={(index) => {
              const entry = exports[index];
              return (
                <button
                  className="flex h-[27px] w-full items-center gap-2 px-2.5 text-left hover:bg-obsidian-750/70"
                  onClick={() => onNavigate({ address: entry.address }, "disassembly")}
                  title={entry.name}
                >
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink-300">
                    {entry.name}
                  </span>
                  <span className="shrink-0 font-mono text-[9.5px] text-accent-400/80">
                    {formatHex(entry.address)}
                  </span>
                </button>
              );
            }}
          />
        )}
      </div>

      <div className="flex h-6 shrink-0 items-center justify-between border-t border-edge px-2.5 font-mono text-[9.5px] text-ink-500">
        <span>
          {tab === "sections" && `${binary.sections.length} sections`}
          {tab === "symbols" &&
            `${symbols.length}/${binary.symbols.length} symbols`}
          {tab === "imports" && `${imports.length} imports`}
          {tab === "exports" && `${exports.length} exports`}
        </span>
        <span>{annotations.length} notes</span>
      </div>
    </aside>
  );
}
