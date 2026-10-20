import { useMemo, useState } from "react";
import {
  AlertTriangle,
  Binary,
  Braces,
  Loader2,
  ScanSearch,
  Search,
  TextCursorInput,
} from "lucide-react";
import type {
  BinaryOpenResult,
  NavigateFn,
  Selection,
  StringScanResult,
} from "../lib/types";
import { formatHex, formatSize, normalizeAddress, parseHex } from "../lib/format";
import { VirtualList } from "./VirtualList";

interface StringsViewProps {
  binary: BinaryOpenResult;
  strings: StringScanResult | null;
  scanning: boolean;
  selection: Selection | null;
  onScan: (minLength: number, ascii: boolean, utf16: boolean) => void;
  onNavigate: NavigateFn;
}

type EncodingFilter = "all" | "ASCII" | "UTF-16LE";

export function StringsView({
  binary,
  strings,
  scanning,
  selection,
  onScan,
  onNavigate,
}: StringsViewProps) {
  const [minLength, setMinLength] = useState("4");
  const [ascii, setAscii] = useState(true);
  const [utf16, setUtf16] = useState(true);
  const [filter, setFilter] = useState("");
  const [encoding, setEncoding] = useState<EncodingFilter>("all");

  const filtered = useMemo(() => {
    if (!strings) return [];
    const needle = filter.trim().toLowerCase();
    return strings.strings.filter((entry) => {
      if (encoding !== "all" && entry.encoding !== encoding) return false;
      if (!needle) return true;
      return (
        entry.value.toLowerCase().includes(needle) ||
        entry.address?.toLowerCase().includes(needle) ||
        entry.offset.toLowerCase().includes(needle)
      );
    });
  }, [strings, filter, encoding]);

  const selectedAddress = normalizeAddress(selection?.address);
  const selectedOffset = normalizeAddress(selection?.fileOffset);

  const runScan = () => {
    const value = Number.parseInt(minLength, 10);
    const bounded = Number.isFinite(value) ? Math.min(512, Math.max(2, value)) : 4;
    setMinLength(String(bounded));
    onScan(bounded, ascii, utf16);
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-edge bg-obsidian-850 px-3 py-2">
        <label className="flex items-center gap-1.5 text-[11px] text-ink-400">
          <TextCursorInput className="size-3.5" />
          Min length
          <input
            className="input h-6.5 w-14 px-1.5 text-center font-mono text-[11px]"
            type="number"
            min={2}
            max={512}
            value={minLength}
            onChange={(event) => setMinLength(event.target.value)}
          />
        </label>

        <button
          className={`flex h-6.5 items-center gap-1 rounded border px-1.5 font-mono text-[10px] transition-colors ${
            ascii
              ? "border-accent-500/40 bg-accent-500/10 text-accent-300"
              : "border-edge-strong bg-obsidian-750 text-ink-500"
          }`}
          onClick={() => setAscii((value) => !value)}
          title="Toggle ASCII scan"
        >
          ASCII
        </button>
        <button
          className={`flex h-6.5 items-center gap-1 rounded border px-1.5 font-mono text-[10px] transition-colors ${
            utf16
              ? "border-accent-500/40 bg-accent-500/10 text-accent-300"
              : "border-edge-strong bg-obsidian-750 text-ink-500"
          }`}
          onClick={() => setUtf16((value) => !value)}
          title="Toggle UTF-16LE scan"
        >
          UTF-16LE
        </button>

        <button
          className="btn h-6.5 px-2 text-[11px]"
          onClick={runScan}
          disabled={scanning || (!ascii && !utf16)}
        >
          {scanning ? (
            <Loader2 className="size-3.5 animate-spin" />
          ) : (
            <ScanSearch className="size-3.5 text-accent-300" />
          )}
          {scanning ? "Scanning…" : "Scan"}
        </button>

        <div className="h-5 w-px bg-edge" />

        <div className="relative min-w-48 flex-1">
          <Search className="pointer-events-none absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-ink-500" />
          <input
            className="input h-6.5 pl-7 text-[11px]"
            placeholder="Filter strings, addresses or offsets…"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            spellCheck={false}
          />
        </div>

        <div className="flex overflow-hidden rounded border border-edge-strong">
          {(["all", "ASCII", "UTF-16LE"] as EncodingFilter[]).map((value) => (
            <button
              key={value}
              className={`h-6.5 px-2 text-[10px] transition-colors ${
                encoding === value
                  ? "bg-accent-500/15 text-accent-300"
                  : "bg-obsidian-800 text-ink-500 hover:text-ink-300"
              }`}
              onClick={() => setEncoding(value)}
            >
              {value === "all" ? "All" : value === "ASCII" ? "ASCII" : "UTF-16"}
            </button>
          ))}
        </div>
      </div>

      {(strings?.truncated || (strings && strings.strings.length === 0)) && (
        <div className="flex shrink-0 items-center gap-2 border-b border-amber-500/20 bg-amber-500/5 px-3 py-1 text-[10.5px] text-amber-300/90">
          <AlertTriangle className="size-3" />
          {strings.truncated
            ? "Result limit reached — increase the minimum length to narrow the scan."
            : "No strings matched the selected encodings and minimum length."}
        </div>
      )}

      <div className="grid h-6 shrink-0 grid-cols-[92px_104px_74px_54px_1fr] items-center border-b border-edge bg-obsidian-900 px-3 font-mono text-[9.5px] uppercase tracking-wider text-ink-500 select-none">
        <span>Offset</span>
        <span>Address</span>
        <span>Encoding</span>
        <span className="text-right">Length</span>
        <span className="pl-3">Value</span>
      </div>

      <div className="min-h-0 flex-1">
        {!strings && !scanning && (
          <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center">
            <Braces className="size-7 text-ink-600" />
            <div className="text-[12px] font-medium text-ink-300">
              Strings have not been scanned yet
            </div>
            <div className="max-w-sm text-[11px] leading-relaxed text-ink-500">
              Choose the encodings and minimum length, then run a scan. Results
              are extracted from the raw file on disk.
            </div>
          </div>
        )}

        {scanning && (
          <div className="flex h-full items-center justify-center gap-2 text-[11.5px] text-ink-500">
            <Loader2 className="size-4 animate-spin text-accent-400" />
            Scanning binary for printable sequences…
          </div>
        )}

        {strings && !scanning && filtered.length === 0 && (
          <div className="flex h-full flex-col items-center justify-center gap-1 p-6 text-center">
            <ScanSearch className="size-6 text-ink-600" />
            <div className="text-[11.5px] text-ink-400">
              No strings match the current filters.
            </div>
          </div>
        )}

        {strings && !scanning && filtered.length > 0 && (
          <VirtualList
            className="h-full"
            count={filtered.length}
            estimateSize={26}
            renderRow={(index) => {
              const entry = filtered[index];
              const address = normalizeAddress(entry.address);
              const offset = normalizeAddress(entry.offset);
              const selected =
                (address != null && address === selectedAddress) ||
                (offset != null && offset === selectedOffset);
              const section = address
                ? binary.sections.find((candidate) => {
                    const start = parseHex(candidate.address);
                    const value = parseHex(address);
                    if (start == null || value == null) return false;
                    return value >= start && value < start + BigInt(candidate.size);
                  })
                : undefined;
              const destination = section?.executable ? "disassembly" : "hex";
              return (
                <button
                  className={`grid h-[26px] w-full grid-cols-[92px_104px_74px_54px_1fr] items-center border-l-2 px-3 text-left font-mono text-[11px] transition-colors ${
                    selected
                      ? "border-accent-400 bg-accent-500/10"
                      : "border-transparent hover:bg-obsidian-850/80"
                  }`}
                  onClick={() =>
                    onNavigate(
                      { address: entry.address, fileOffset: entry.offset },
                      destination,
                    )
                  }
                  title={`${entry.section ?? "unmapped"} · ${entry.length} chars`}
                >
                  <span className="text-ink-500">{formatHex(entry.offset)}</span>
                  <span className="text-accent-400/90">
                    {address ? formatHex(address) : "—"}
                  </span>
                  <span>
                    <span
                      className={`rounded px-1 text-[9px] ${
                        entry.encoding === "ASCII"
                          ? "bg-sky-500/10 text-sky-300"
                          : "bg-violet-500/10 text-violet-300"
                      }`}
                    >
                      {entry.encoding}
                    </span>
                  </span>
                  <span className="pr-1 text-right text-ink-500">{entry.length}</span>
                  <span
                    className="truncate pl-3 text-ink-200"
                    title={entry.value}
                  >
                    {entry.value}
                  </span>
                </button>
              );
            }}
          />
        )}
      </div>

      <div className="flex h-6 shrink-0 items-center gap-3 border-t border-edge bg-obsidian-900 px-3 font-mono text-[9.5px] text-ink-500">
        {strings ? (
          <>
            <span className="flex items-center gap-1">
              <Binary className="size-3" />
              {strings.strings.length.toLocaleString()} strings
            </span>
            <span className="text-ink-600">|</span>
            <span>ASCII {strings.asciiCount.toLocaleString()}</span>
            <span>UTF-16 {strings.utf16Count.toLocaleString()}</span>
            <span className="text-ink-600">|</span>
            <span>scanned {formatSize(strings.scannedBytes)}</span>
            <span className="text-ink-600">|</span>
            <span>
              showing {filtered.length.toLocaleString()}
              {filter || encoding !== "all" ? " filtered" : ""}
            </span>
          </>
        ) : (
          <span>No scan results</span>
        )}
        <div className="flex-1" />
        <span className="text-ink-600">
          click a row to jump · {binary.info.fileName}
        </span>
      </div>
    </div>
  );
}
