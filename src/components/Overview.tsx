import {
  AlertTriangle,
  ArrowUpRight,
  Binary,
  Boxes,
  Cpu,
  Database,
  FileCode2,
  Fingerprint,
  HardDrive,
  Layers,
  MapPin,
  PackageOpen,
} from "lucide-react";
import type {
  BinaryOpenResult,
  NavigateFn,
  ProjectInfo,
} from "../lib/types";
import { formatHex, formatSize, shorten } from "../lib/format";

interface OverviewProps {
  binary: BinaryOpenResult;
  project: ProjectInfo | null;
  onNavigate: NavigateFn;
}

function Fact({
  icon: Icon,
  label,
  value,
  mono = false,
  title,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  title?: string;
}) {
  return (
    <div className="rounded-lg border border-edge bg-obsidian-850 p-3">
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-500">
        <Icon className="size-3" />
        {label}
      </div>
      <div
        className={`mt-1.5 truncate text-[12.5px] text-ink-200 ${mono ? "font-mono" : ""}`}
        title={title ?? (typeof value === "string" ? value : undefined)}
      >
        {value}
      </div>
    </div>
  );
}

export function Overview({ binary, project, onNavigate }: OverviewProps) {
  const { info, sections, imports, exports, symbols } = binary;
  const executableSections = sections.filter((section) => section.executable);

  return (
    <div className="h-full overflow-auto p-4">
      <div className="mx-auto max-w-5xl space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Binary className="size-4 text-accent-400" />
              <h1 className="truncate text-[16px] font-semibold text-ink-100">
                {info.fileName}
              </h1>
              <span className="rounded border border-accent-500/30 bg-accent-500/10 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-accent-300">
                {info.format}
              </span>
            </div>
            <div
              className="mt-1 truncate font-mono text-[10.5px] text-ink-500"
              title={info.path}
            >
              {info.path}
            </div>
          </div>
          <div className="shrink-0 text-right">
            <div className="text-[10px] uppercase tracking-[0.14em] text-ink-500">
              SHA-256
            </div>
            <div
              className="mt-0.5 font-mono text-[10.5px] text-ink-400"
              title={info.sha256}
            >
              {shorten(info.sha256, 14, 12)}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2.5 md:grid-cols-4">
          <Fact
            icon={Cpu}
            label="Architecture"
            value={`${info.architecture} · ${info.bitness}-bit`}
            mono
          />
          <Fact icon={HardDrive} label="File size" value={formatSize(info.fileSize)} />
          <Fact icon={MapPin} label="Image base" value={formatHex(info.imageBase, 16)} mono />
          <Fact icon={FileCode2} label="Object kind" value={info.objectKind} />
          <Fact
            icon={ArrowUpRight}
            label="Entry point"
            value={
              info.entryPoint ? (
                <button
                  className="font-mono text-accent-300 hover:underline"
                  onClick={() => onNavigate({ address: info.entryPoint }, "disassembly")}
                >
                  {formatHex(info.entryPoint, 16)}
                </button>
              ) : (
                "—"
              )
            }
            mono
          />
          <Fact icon={Layers} label="Sections" value={String(info.sectionCount)} />
          <Fact icon={Boxes} label="Symbols" value={String(info.symbolCount)} />
          <Fact
            icon={PackageOpen}
            label="Imports / Exports"
            value={`${imports.length} / ${exports.length}`}
          />
        </div>

        {(info.warnings.length > 0 || !info.hasSymbols) && (
          <div className="space-y-1.5 rounded-lg border border-amber-500/25 bg-amber-500/5 p-3">
            {info.warnings.map((warning) => (
              <div
                key={warning}
                className="flex items-start gap-2 text-[11.5px] text-amber-300/90"
              >
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                {warning}
              </div>
            ))}
            {!info.hasSymbols && (
              <div className="flex items-start gap-2 text-[11.5px] text-amber-300/80">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                No symbol table found — the binary may be stripped.
              </div>
            )}
          </div>
        )}

        <section className="overflow-hidden rounded-lg border border-edge bg-obsidian-850">
          <div className="flex items-center justify-between border-b border-edge bg-obsidian-800 px-3 py-2">
            <div className="flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[0.14em] text-ink-400">
              <Layers className="size-3.5" />
              Sections
            </div>
            <div className="font-mono text-[10.5px] text-ink-500">
              {executableSections.length} executable
            </div>
          </div>
          <table className="w-full border-collapse text-[11.5px]">
            <thead>
              <tr className="border-b border-edge text-left text-[10px] uppercase tracking-wider text-ink-500">
                <th className="px-3 py-1.5 font-medium">Name</th>
                <th className="px-3 py-1.5 font-medium">Address</th>
                <th className="px-3 py-1.5 font-medium">File offset</th>
                <th className="px-3 py-1.5 font-medium">Perms</th>
                <th className="px-3 py-1.5 text-right font-medium">Size</th>
                <th className="px-3 py-1.5 font-medium">Kind</th>
              </tr>
            </thead>
            <tbody>
              {sections.map((section) => (
                <tr
                  key={`${section.name}-${section.address}`}
                  className="cursor-pointer border-b border-edge/50 transition-colors last:border-0 hover:bg-obsidian-750/70"
                  onClick={() =>
                    onNavigate(
                      {
                        address: section.address,
                        fileOffset: section.fileOffset,
                      },
                      section.executable ? "disassembly" : "hex",
                    )
                  }
                >
                  <td className="px-3 py-1.5 font-mono text-accent-300">
                    {section.name}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-ink-300">
                    {formatHex(section.address)}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-ink-400">
                    {section.fileOffset ? formatHex(section.fileOffset) : "—"}
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={`rounded px-1 font-mono text-[10.5px] ${
                        section.executable
                          ? "bg-accent-500/10 text-accent-300"
                          : section.writable
                            ? "bg-amber-500/10 text-amber-300"
                            : "bg-obsidian-700 text-ink-400"
                      }`}
                    >
                      {section.permissions}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-ink-300">
                    {formatSize(section.size)}
                  </td>
                  <td className="px-3 py-1.5 text-ink-500">{section.kind}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <div className="grid grid-cols-2 gap-4">
          <section className="overflow-hidden rounded-lg border border-edge bg-obsidian-850">
            <div className="flex items-center justify-between border-b border-edge bg-obsidian-800 px-3 py-2">
              <div className="flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[0.14em] text-ink-400">
                <PackageOpen className="size-3.5" />
                Imports
              </div>
              <span className="font-mono text-[10.5px] text-ink-500">
                {imports.length}
              </span>
            </div>
            <div className="max-h-56 overflow-auto">
              {imports.length === 0 ? (
                <div className="p-3 text-[11.5px] text-ink-500">
                  No imports recorded.
                </div>
              ) : (
                imports.slice(0, 200).map((entry, index) => (
                  <div
                    key={`${entry.library ?? "?"}-${entry.name}-${index}`}
                    className="flex items-center justify-between gap-2 border-b border-edge/40 px-3 py-1 font-mono text-[11px] last:border-0"
                  >
                    <span className="truncate text-ink-200">{entry.name}</span>
                    <span className="shrink-0 text-[10px] text-ink-500">
                      {entry.library ?? "—"}
                    </span>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="overflow-hidden rounded-lg border border-edge bg-obsidian-850">
            <div className="flex items-center justify-between border-b border-edge bg-obsidian-800 px-3 py-2">
              <div className="flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[0.14em] text-ink-400">
                <Fingerprint className="size-3.5" />
                Exports
              </div>
              <span className="font-mono text-[10.5px] text-ink-500">
                {exports.length}
              </span>
            </div>
            <div className="max-h-56 overflow-auto">
              {exports.length === 0 ? (
                <div className="p-3 text-[11.5px] text-ink-500">
                  No exports recorded.
                </div>
              ) : (
                exports.slice(0, 200).map((entry) => (
                  <button
                    key={`${entry.name}-${entry.address}`}
                    className="flex w-full items-center justify-between gap-2 border-b border-edge/40 px-3 py-1 text-left font-mono text-[11px] last:border-0 hover:bg-obsidian-750/70"
                    onClick={() => onNavigate({ address: entry.address }, "disassembly")}
                  >
                    <span className="truncate text-ink-200">{entry.name}</span>
                    <span className="shrink-0 text-[10px] text-accent-400">
                      {formatHex(entry.address)}
                    </span>
                  </button>
                ))
              )}
            </div>
          </section>
        </div>

        {project && (
          <div className="flex items-center gap-2 rounded-lg border border-edge bg-obsidian-850 px-3 py-2 text-[11.5px] text-ink-400">
            <Database className="size-3.5 text-emerald-400" />
            <span className="font-medium text-ink-300">{project.name}</span>
            <span className="text-ink-600">·</span>
            <span>schema v{project.schemaVersion}</span>
            <span className="text-ink-600">·</span>
            <span>{symbols.length} symbols indexed</span>
          </div>
        )}
      </div>
    </div>
  );
}
