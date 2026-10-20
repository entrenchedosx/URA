import { useEffect, useMemo, useRef, useState } from "react";
import { Crosshair, FileDigit, Hash, Loader2, Search } from "lucide-react";
import {
  errorMessage,
  listFunctions,
} from "../lib/api";
import {
  formatHex,
  normalizeAddress,
  parseHex,
  sectionForAddress,
} from "../lib/format";
import type { FunctionSummary } from "../lib/types";
import { useMessages } from "../state/messages";
import { useSession } from "../state/session";

interface GoToDialogProps {
  open: boolean;
  onClose: () => void;
}

interface GoToCandidate {
  key: string;
  label: string;
  detail: string;
  kind: string;
  address?: string;
  fileOffset?: string;
}

const OFFSET_PATTERN = /^(?:@|file:|offset\s+)(0x[0-9a-f_]+|[0-9a-f_]+)$/i;
const ADDRESS_PATTERN = /^(?:0x[0-9a-f_]+|[0-9a-f_]{6,})$/i;
const RELATIVE_PATTERN = /^([+-])\s*(0x[0-9a-f_]+|[0-9a-f_]+)$/i;
const SECTION_RELATIVE_PATTERN =
  /^([A-Za-z_.$][\w.$-]*)\s*([+-])\s*(0x[0-9a-f_]+|[0-9a-f_]+)$/i;

function parseOffsetInput(query: string): string | null {
  const match = OFFSET_PATTERN.exec(query.trim());
  if (!match) return null;
  const parsed = parseHex(match[1]);
  return parsed == null ? null : formatHex(parsed);
}

function parsePastedAddress(query: string): string | null {
  const tokens = query.trim().split(/[\s:]+/).filter(Boolean);
  if (tokens.length < 3) return null;
  if (!/^(?:0x)?[0-9a-f]{8,16}$/i.test(tokens[0])) return null;
  if (!tokens.slice(1).every((token) => /^[0-9a-f]{1,4}$/i.test(token))) {
    return null;
  }
  const parsed = parseHex(tokens[0]);
  return parsed == null ? null : formatHex(parsed);
}

export function GoToDialog({ open, onClose }: GoToDialogProps) {
  const {
    binary,
    project,
    analysis,
    selection,
    navigate,
  } = useSession();
  const { log } = useMessages();
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const [functions, setFunctions] = useState<FunctionSummary[]>([]);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setSelected(0);
    setFunctions([]);
    setError(null);
    const frame = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(frame);
  }, [open]);

  const trimmed = query.trim();
  const offsetInput = parseOffsetInput(trimmed);
  const looksNumeric =
    !offsetInput && ADDRESS_PATTERN.test(trimmed.replace(/^@/, ""));
  const pastedAddress = offsetInput || looksNumeric ? null : parsePastedAddress(trimmed);
  const relativeMatch = RELATIVE_PATTERN.exec(trimmed);
  const sectionMatch = SECTION_RELATIVE_PATTERN.exec(trimmed);
  const sectionRelative = useMemo(() => {
    if (!sectionMatch || !binary) return null;
    const name = sectionMatch[1].toLowerCase();
    const section = binary.sections.find(
      (entry) => entry.name.toLowerCase() === name,
    );
    if (!section) return null;
    const delta = parseHex(sectionMatch[3]);
    if (delta == null) return null;
    const base = parseHex(section.address);
    if (base == null) return null;
    const value =
      sectionMatch[2] === "-" ? base - delta : base + delta;
    if (value < 0n) return null;
    return {
      address: formatHex(value),
      label: `${section.name} ${sectionMatch[2]} ${formatHex(delta)}`,
    };
  }, [binary, sectionMatch]);
  const relativeAddress = useMemo(() => {
    if (!relativeMatch || !selection?.address) return null;
    const delta = parseHex(relativeMatch[2]);
    const base = parseHex(selection.address);
    if (delta == null || base == null) return null;
    const value =
      relativeMatch[1] === "-" ? base - delta : base + delta;
    if (value < 0n) return null;
    return formatHex(value);
  }, [relativeMatch, selection?.address]);
  const specialAddress =
    sectionRelative?.address ?? pastedAddress ?? relativeAddress;
  const specialLabel = sectionRelative
    ? `Section-relative ${sectionRelative.label}`
    : pastedAddress
      ? "Pasted dump address"
      : relativeAddress
        ? `Relative ${relativeMatch?.[1]} ${formatHex(parseHex(relativeMatch?.[2]) ?? 0n)} from ${formatHex(selection?.address ?? 0)}`
        : null;

  useEffect(() => {
    if (!open || !analysis || !trimmed || offsetInput || specialAddress) {
      setFunctions([]);
      setSearching(false);
      return;
    }
    let cancelled = false;
    setSearching(true);
    const timeout = window.setTimeout(() => {
      listFunctions({ search: trimmed, limit: 12 })
        .then((page) => {
          if (!cancelled) setFunctions(page.functions);
        })
        .catch((err) => {
          if (!cancelled) log("warning", `Function search failed: ${errorMessage(err)}`);
        })
        .finally(() => {
          if (!cancelled) setSearching(false);
        });
    }, 140);
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [open, analysis, trimmed, offsetInput, specialAddress, log]);

  const candidates = useMemo<GoToCandidate[]>(() => {
    if (!binary || !trimmed || offsetInput || specialAddress) return [];
    if (looksNumeric) return [];
    const needle = trimmed.toLowerCase();
    const results: GoToCandidate[] = [];
    const seen = new Set<string>();
    const push = (candidate: GoToCandidate) => {
      const key = `${candidate.address ?? candidate.fileOffset}:${candidate.label}`;
      if (seen.has(key)) return;
      seen.add(key);
      results.push(candidate);
    };

    for (const fn of functions.slice(0, 8)) {
      push({
        key: `function-${fn.address}`,
        label: fn.name,
        detail: fn.address,
        kind: fn.origin === "user" ? "user function" : "function",
        address: fn.address,
      });
    }
    let sectionMatches = 0;
    for (const section of binary.sections) {
      if (sectionMatches >= 4) break;
      if (!section.name.toLowerCase().includes(needle)) continue;
      sectionMatches += 1;
      push({
        key: `section-${section.name}`,
        label: section.name,
        detail: `${section.address} · ${section.executable ? "executable" : "data"}`,
        kind: "section",
        address: section.address,
      });
    }
    let symbolMatches = 0;
    for (const symbol of binary.symbols) {
      if (symbolMatches >= 6) break;
      if (!symbol.defined || !symbol.address) continue;
      if (!symbol.name.toLowerCase().includes(needle)) continue;
      symbolMatches += 1;
      push({
        key: `symbol-${symbol.name}-${symbol.address}`,
        label: symbol.name,
        detail: symbol.address,
        kind: "symbol",
        address: symbol.address,
      });
    }
    let exportMatches = 0;
    for (const entry of binary.exports) {
      if (exportMatches >= 6) break;
      if (!entry.name.toLowerCase().includes(needle)) continue;
      exportMatches += 1;
      push({
        key: `export-${entry.name}`,
        label: entry.name,
        detail: entry.address,
        kind: "export",
        address: entry.address,
      });
    }
    for (const annotation of project?.annotations ?? []) {
      const label = annotation.label ?? annotation.note;
      if (!label.toLowerCase().includes(needle)) continue;
      push({
        key: `annotation-${annotation.id}`,
        label,
        detail: annotation.address,
        kind: "annotation",
        address: annotation.address,
      });
      if (results.length >= 24) break;
    }
    return results.slice(0, 24);
  }, [
    binary,
    project?.annotations,
    functions,
    trimmed,
    offsetInput,
    looksNumeric,
    specialAddress,
  ]);

  useEffect(() => {
    setSelected(0);
  }, [trimmed]);

  if (!open) return null;

  const submitNumeric = () => {
    if (!binary) return;
    if (offsetInput) {
      const parsed = parseHex(offsetInput);
      if (parsed == null || parsed >= BigInt(binary.info.fileSize)) {
        setError("File offset is outside the binary.");
        return;
      }
      onClose();
      navigate({ fileOffset: offsetInput }, "hex");
      return;
    }
    const normalized = normalizeAddress(trimmed);
    if (!normalized) {
      setError("Enter a hexadecimal address such as 0x140001000.");
      return;
    }
    if (!sectionForAddress(binary.sections, normalized)) {
      setError(
        `${normalized} is not mapped by any section. Use @${normalized} to open a file offset.`,
      );
      return;
    }
    onClose();
    const section = sectionForAddress(binary.sections, normalized);
    navigate(
      { address: normalized },
      section?.executable ? "disassembly" : "hex",
    );
  };

  const submitSpecial = () => {
    if (!binary || !specialAddress) {
      setError("That address cannot be resolved in the loaded binary.");
      return;
    }
    const section = sectionForAddress(binary.sections, specialAddress);
    if (!section) {
      setError(`${specialAddress} is not mapped by any section.`);
      return;
    }
    onClose();
    navigate(
      { address: specialAddress },
      section.executable ? "disassembly" : "hex",
    );
  };

  const submitCandidate = (candidate: GoToCandidate | undefined) => {
    if (!candidate) {
      if (looksNumeric || offsetInput) submitNumeric();
      else setError("No matching address, symbol or function.");
      return;
    }
    onClose();
    navigate({ address: candidate.address, fileOffset: candidate.fileOffset });
  };

  const submit = () => {
    setError(null);
    if (specialAddress) {
      submitSpecial();
      return;
    }
    if (relativeMatch && !relativeAddress) {
      setError("Relative go-to needs a selected address and a valid delta.");
      return;
    }
    if (offsetInput || looksNumeric) {
      submitNumeric();
      return;
    }
    submitCandidate(candidates[selected]);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/55 px-4 pt-[14vh] backdrop-blur-[2px]"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-[560px] overflow-hidden rounded-xl border border-edge-strong bg-obsidian-850 shadow-[0_24px_80px_rgba(0,0,0,0.65)]">
        <div className="flex items-center gap-2 border-b border-edge bg-obsidian-800 px-3">
          <Crosshair className="size-4 shrink-0 text-accent-400" />
          <input
            ref={inputRef}
            className="h-11 flex-1 bg-transparent font-mono text-[13px] text-ink-100 placeholder:text-ink-500 focus:outline-none"
            placeholder="Address, @offset, section+offset, +delta or symbol"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setError(null);
            }}
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                event.preventDefault();
                onClose();
              } else if (event.key === "ArrowDown") {
                event.preventDefault();
                setSelected((value) =>
                  candidates.length === 0
                    ? 0
                    : (value + 1) % candidates.length,
                );
              } else if (event.key === "ArrowUp") {
                event.preventDefault();
                setSelected((value) =>
                  candidates.length === 0
                    ? 0
                    : (value - 1 + candidates.length) % candidates.length,
                );
              } else if (event.key === "Enter") {
                event.preventDefault();
                submit();
              }
            }}
            spellCheck={false}
          />
          {searching ? (
            <Loader2 className="size-3.5 animate-spin text-accent-400" />
          ) : (
            <span className="kbd">Enter</span>
          )}
        </div>

        <div className="max-h-[320px] overflow-auto py-1">
          {specialAddress && (
            <button
              className="flex w-full items-center gap-2.5 bg-accent-500/10 px-3 py-2 text-left"
              onClick={() => {
                setError(null);
                submitSpecial();
              }}
            >
              <Hash className="size-4 shrink-0 text-accent-300" />
              <span className="min-w-0 flex-1">
                <span className="block font-mono text-[12.5px] text-ink-200">
                  {specialAddress}
                </span>
                <span className="block text-[10px] text-ink-500">
                  {specialLabel}
                </span>
              </span>
            </button>
          )}

          {offsetInput && (
            <button
              className="flex w-full items-center gap-2.5 bg-accent-500/10 px-3 py-2 text-left"
              onClick={() => {
                setError(null);
                submitNumeric();
              }}
            >
              <FileDigit className="size-4 shrink-0 text-accent-300" />
              <span className="min-w-0 flex-1">
                <span className="block font-mono text-[12.5px] text-ink-200">
                  File offset {offsetInput}
                </span>
                <span className="block text-[10px] text-ink-500">
                  Explicit offset syntax
                </span>
              </span>
            </button>
          )}

          {looksNumeric && !offsetInput && (
            <button
              className="flex w-full items-center gap-2.5 bg-accent-500/10 px-3 py-2 text-left"
              onClick={() => {
                setError(null);
                submitNumeric();
              }}
            >
              <Hash className="size-4 shrink-0 text-accent-300" />
              <span className="min-w-0 flex-1">
                <span className="block font-mono text-[12.5px] text-ink-200">
                  Address {normalizeAddress(trimmed) ?? trimmed}
                </span>
                <span className="block text-[10px] text-ink-500">
                  Virtual address
                </span>
              </span>
            </button>
          )}

          {!offsetInput &&
            !looksNumeric &&
            !specialAddress &&
            candidates.map((candidate, index) => (
              <button
                key={candidate.key}
                className={`flex w-full items-center gap-2.5 px-3 py-2 text-left transition-colors ${
                  index === selected ? "bg-accent-500/12" : "hover:bg-obsidian-800"
                }`}
                onMouseEnter={() => setSelected(index)}
                onClick={() => submitCandidate(candidate)}
              >
                <Search
                  className={`size-4 shrink-0 ${
                    index === selected ? "text-accent-300" : "text-ink-500"
                  }`}
                />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-[12.5px] text-ink-200">
                    {candidate.label}
                  </span>
                  <span className="block font-mono text-[10px] text-ink-500">
                    {candidate.detail}
                  </span>
                </span>
                <span className="shrink-0 text-[9px] uppercase tracking-wider text-ink-600">
                  {candidate.kind}
                </span>
              </button>
            ))}

          {!offsetInput &&
            !looksNumeric &&
            !specialAddress &&
            !searching &&
            candidates.length === 0 &&
            trimmed.length > 0 && (
              <div className="px-4 py-8 text-center text-[11.5px] text-ink-500">
                No matching address, symbol or function.
              </div>
            )}

          {!trimmed && (
            <div className="px-4 py-6 text-center text-[11px] leading-relaxed text-ink-500">
              Enter a hexadecimal virtual address, an explicit file offset
              (<span className="font-mono text-ink-400">@0x…</span>), or a
              symbol or function name.
            </div>
          )}
        </div>

        {error && (
          <div className="border-t border-red-500/25 bg-red-500/5 px-3 py-2 text-[10.5px] text-red-300/90">
            {error}
          </div>
        )}

        <div className="flex items-center gap-3 border-t border-edge bg-obsidian-900 px-3 py-1.5 font-mono text-[9.5px] text-ink-500">
          <span>0x… address</span>
          <span>@0x… offset</span>
          <span>.text+0x10</span>
          <div className="flex-1" />
          <span>Esc close</span>
        </div>
      </div>
    </div>
  );
}
