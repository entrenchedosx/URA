import { useMemo, useState } from "react";
import {
  BookMarked,
  Fingerprint,
  Layers,
  PackageOpen,
  Search,
  Tags,
} from "lucide-react";
import type { Annotation, SectionView } from "../lib/types";
import { formatHex, formatSize, normalizeAddress } from "../lib/format";
import { useSession } from "../state/session";
import { VirtualList } from "./VirtualList";

type ExplorerTab = "sections" | "symbols" | "imports" | "exports";

const tabs: Array<{
  id: ExplorerTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: "sections", label: "Sections", icon: Layers },
  { id: "symbols", label: "Symbols", icon: Tags },
  { id: "imports", label: "Imports", icon: PackageOpen },
  { id: "exports", label: "Exports", icon: Fingerprint },
];

function sectionContains(section: SectionView, address: string | null): boolean {
  if (!address) return false;
  const parsed = normalizeAddress(address);
  if (!parsed) return false;
  try {
    const start = BigInt(section.address);
    const value = BigInt(parsed);
    return value >= start && value < start + BigInt(section.size);
  } catch {
    return false;
  }
}

export function Explorer() {
  const { binary, project, selection, navigate } = useSession();
  const [tab, setTab] = useState<ExplorerTab>("sections");
  const [filter, setFilter] = useState("");

  const annotations = project?.annotations ?? [];

  const annotated = useMemo(() => {
    const map = new Map<string, Annotation>();
    for (const annotation of annotations) {
      const address = normalizeAddress(annotation.address);
      if (address) map.set(address, annotation);
    }
    return map;
  }, [annotations]);

  const needle = filter.trim().toLowerCase();

  const sections = useMemo(() => {
    if (!binary) return [];
    if (!needle) return binary.sections;
    return binary.sections.filter(
      (section) =>
        section.name.toLowerCase().includes(needle) ||
        section.address.toLowerCase().includes(needle) ||
        section.kind.toLowerCase().includes(needle),
    );
  }, [binary, needle]);

  const symbols = useMemo(() => {
    if (!binary) return [];
    if (!needle) return binary.symbols;
    return binary.symbols.filter(
      (symbol) =>
        symbol.name.toLowerCase().includes(needle) ||
        (symbol.section ?? "").toLowerCase().includes(needle) ||
        (symbol.address ?? "").toLowerCase().includes(needle),
    );
  }, [binary, needle]);

  const imports = useMemo(() => {
    if (!binary) return [];
    if (!needle) return binary.imports;
    return binary.imports.filter(
      (entry) =>
        entry.name.toLowerCase().includes(needle) ||
        (entry.library ?? "").toLowerCase().includes(needle),
    );
  }, [binary, needle]);

  const exports = useMemo(() => {
    if (!binary) return [];
    if (!needle) return binary.exports;
    return binary.exports.filter(
      (entry) =>
        entry.name.toLowerCase().includes(needle) ||
        entry.address.toLowerCase().includes(needle),
    );
  }, [binary, needle]);

  if (!binary) {
    return (
      <div className="flex h-full items-center justify-center bg-obsidian-850 p-6 text-[11.5px] text-ink-500">
        Open a binary to browse its structure.
      </div>
    );
  }

  const counts: Record<ExplorerTab, number> = {
    sections: sections.length,
    symbols: symbols.length,
    imports: imports.length,
    exports: exports.length,
  };

  return (
    <div className="explorer-root flex h-full min-h-0 w-full flex-col bg-obsidian-850">
      <div className="flex h-7 shrink-0 items-center justify-between border-b border-edge px-2.5">
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ink-500">
          {binary.info.format} · {binary.info.architecture}
        </span>
        <span className="font-mono text-[9.5px] text-ink-600">
          {annotations.length} {annotations.length === 1 ? "note" : "notes"}
        </span>
      </div>

      <div className="grid shrink-0 grid-cols-4 border-b border-edge">
        {tabs.map((entry) => {
          const Icon = entry.icon;
          const active = tab === entry.id;
          return (
            <button
              key={entry.id}
              className={`relative flex h-8 items-center justify-center gap-1 border-b-2 text-[10.5px] font-medium transition-colors ${
                active
                  ? "border-accent-500 bg-obsidian-800 text-accent-300"
                  : "border-transparent text-ink-500 hover:bg-obsidian-800/60 hover:text-ink-300"
              }`}
              onClick={() => setTab(entry.id)}
              title={entry.label}
            >
              <Icon className="size-3 shrink-0" />
              <span className="explorer-tab-label truncate text-[9.5px]">
                {entry.label}
              </span>
              <span className="font-mono text-[8.5px] text-ink-600">
                {counts[entry.id]}
              </span>
            </button>
          );
        })}
      </div>

      <div className="shrink-0 border-b border-edge p-1.5">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-ink-500" />
          <input
            className="input h-6.5 pl-7 text-[11px]"
            placeholder={`Filter ${tab}…`}
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            spellCheck={false}
          />
        </div>
      </div>

      <div className="min-h-0 flex-1">
        {tab === "sections" && (
          <VirtualList
            className="h-full"
            count={sections.length}
            estimateSize={34}
            renderRow={(index) => {
              const section = sections[index];
              const active = sectionContains(section, selection?.address ?? null);
              return (
                <button
                  className={`flex h-[34px] w-full items-center gap-2 border-l-2 px-2.5 text-left transition-colors ${
                    active
                      ? "border-accent-400 bg-accent-500/10"
                      : "border-transparent hover:bg-obsidian-750/70"
                  }`}
                  onClick={() =>
                    navigate(
                      { address: section.address, fileOffset: section.fileOffset },
                      section.executable ? "disassembly" : "hex",
                    )
                  }
                  title={`${section.name} — ${formatSize(section.size)}`}
                >
                  <span
                    className={`h-6 w-0.5 shrink-0 rounded-full ${
                      section.executable
                        ? "bg-accent-500"
                        : section.writable
                          ? "bg-amber-500/70"
                          : "bg-obsidian-600"
                    }`}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-1.5">
                      <span className="truncate font-mono text-[11.5px] text-ink-200">
                        {section.name}
                      </span>
                      {annotated.has(normalizeAddress(section.address) ?? "") && (
                        <BookMarked className="size-3 shrink-0 text-amber-400" />
                      )}
                    </span>
                    <span className="block font-mono text-[9.5px] text-ink-500">
                      {formatHex(section.address)} · {section.permissions}
                    </span>
                  </span>
                  <span className="shrink-0 text-right">
                    <span className="block font-mono text-[9.5px] text-ink-400">
                      {formatSize(section.size)}
                    </span>
                    <span className="explorer-file-offset block font-mono text-[9px] text-ink-600">
                      {section.fileOffset ? formatHex(section.fileOffset) : "no file"}
                    </span>
                  </span>
                </button>
              );
            }}
          />
        )}

        {tab === "symbols" && (
          <VirtualList
            className="h-full"
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
                    navigate(
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
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink-300">
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
            className="h-full"
            count={imports.length}
            estimateSize={30}
            renderRow={(index) => {
              const entry = imports[index];
              return (
                <div className="flex h-[30px] items-center gap-2 px-2.5">
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
            className="h-full"
            count={exports.length}
            estimateSize={27}
            renderRow={(index) => {
              const entry = exports[index];
              return (
                <button
                  className="flex h-[27px] w-full items-center gap-2 px-2.5 text-left hover:bg-obsidian-750/70"
                  onClick={() => navigate({ address: entry.address }, "disassembly")}
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
          {tab === "sections" && `${sections.length} sections`}
          {tab === "symbols" && `${symbols.length}/${binary.symbols.length} symbols`}
          {tab === "imports" && `${imports.length} imports`}
          {tab === "exports" && `${exports.length} exports`}
        </span>
        <span>{filter ? "filtered" : binary.info.fileName}</span>
      </div>
    </div>
  );
}
