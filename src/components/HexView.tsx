import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Binary, CornerDownRight, Hash, Loader2, MoveRight } from "lucide-react";
import { errorMessage, readHex } from "../lib/api";
import {
  addressToOffset,
  formatHex,
  normalizeAddress,
  offsetToAddress,
  parseHex,
  sectionForOffset,
} from "../lib/format";
import type {
  BinaryOpenResult,
  NavigateFn,
  NavigationTarget,
  Selection,
} from "../lib/types";

const ROW_BYTES = 16;
const ROW_HEIGHT = 22;
const CHUNK_BYTES = 4096;
const CHUNK_ROWS = CHUNK_BYTES / ROW_BYTES;

interface HexViewProps {
  binary: BinaryOpenResult;
  target: NavigationTarget;
  selection: Selection | null;
  onSelect: (selection: Selection) => void;
  onNavigate: NavigateFn;
  onLog: (level: "info" | "success" | "warning" | "error", text: string) => void;
}

function isPrintable(byte: number): boolean {
  return byte >= 0x20 && byte <= 0x7e;
}

export function HexView({
  binary,
  target,
  selection,
  onSelect,
  onNavigate,
  onLog,
}: HexViewProps) {
  const fileSize = binary.info.fileSize;
  const totalRows = Math.max(1, Math.ceil(fileSize / ROW_BYTES));
  const chunkCount = Math.max(1, Math.ceil(fileSize / CHUNK_BYTES));

  const [anchor, setAnchor] = useState<bigint>(0n);
  const [jumpValue, setJumpValue] = useState("");
  const [, setChunkVersion] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const chunksRef = useRef<Map<number, Uint8Array>>(new Map());
  const pendingRef = useRef<Set<number>>(new Set());
  const rafRef = useRef<number | null>(null);
  const scrollToken = useRef(0);

  const virtualizer = useVirtualizer({
    count: totalRows,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 32,
  });

  const loadChunk = useCallback(
    (index: number) => {
      if (index < 0 || index >= chunkCount) return;
      if (chunksRef.current.has(index) || pendingRef.current.has(index)) return;
      pendingRef.current.add(index);
      const offset = index * CHUNK_BYTES;
      const length = Math.min(CHUNK_BYTES, fileSize - offset);
      readHex(offset, length)
        .then((page) => {
          chunksRef.current.set(index, new Uint8Array(page.data));
          pendingRef.current.delete(index);
          setChunkVersion((value) => value + 1);
        })
        .catch((err) => {
          pendingRef.current.delete(index);
          setError(errorMessage(err));
          onLog("error", `Hex read failed at ${formatHex(offset)}: ${errorMessage(err)}`);
        });
    },
    [chunkCount, fileSize, onLog],
  );

  const ensureVisible = useCallback(() => {
    const element = scrollRef.current;
    if (!element) return;
    const firstRow = Math.max(0, Math.floor(element.scrollTop / ROW_HEIGHT) - 2);
    const lastRow = Math.min(
      totalRows - 1,
      Math.ceil((element.scrollTop + element.clientHeight) / ROW_HEIGHT) + 2,
    );
    const firstChunk = Math.floor(firstRow / CHUNK_ROWS);
    const lastChunk = Math.floor(lastRow / CHUNK_ROWS);
    for (let index = firstChunk; index <= lastChunk; index += 1) {
      loadChunk(index);
    }
  }, [loadChunk, totalRows]);

  const handleScroll = useCallback(() => {
    if (rafRef.current != null) return;
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = null;
      ensureVisible();
      const element = scrollRef.current;
      if (element) {
        const row = Math.floor(element.scrollTop / ROW_HEIGHT);
        setAnchor(BigInt(row * ROW_BYTES));
      }
    });
  }, [ensureVisible]);

  useEffect(() => {
    const offsetValue =
      parseHex(target.fileOffset) ??
      (target.address ? parseHex(addressToOffset(binary.sections, target.address)) : null) ??
      0n;
    const clamped = offsetValue < 0n
      ? 0n
      : offsetValue >= BigInt(fileSize)
        ? BigInt(Math.max(0, fileSize - 1))
        : offsetValue;
    setAnchor(clamped);
    setJumpValue(formatHex(clamped));
    const row = Math.min(
      Math.max(0, Number(clamped / BigInt(ROW_BYTES))),
      totalRows - 1,
    );
    const token = scrollToken.current + 1;
    scrollToken.current = token;
    const applyScroll = () => {
      if (scrollToken.current !== token) return;
      const element = scrollRef.current;
      if (element) {
        element.scrollTop = Math.max(0, row * ROW_HEIGHT - ROW_HEIGHT * 2);
        ensureVisible();
      }
    };
    const frame = requestAnimationFrame(applyScroll);
    const settleTimer = window.setTimeout(applyScroll, 150);
    const finalTimer = window.setTimeout(applyScroll, 450);
    return () => {
      cancelAnimationFrame(frame);
      window.clearTimeout(settleTimer);
      window.clearTimeout(finalTimer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target.nonce, target.address, target.fileOffset]);

  useEffect(() => {
    const frame = requestAnimationFrame(() => ensureVisible());
    return () => cancelAnimationFrame(frame);
  }, [ensureVisible]);

  useEffect(() => {
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  const selectedOffset = normalizeAddress(selection?.fileOffset);
  const currentSection = sectionForOffset(binary.sections, anchor);

  const jumpTo = useCallback(
    (raw: string) => {
      const parsed = parseHex(raw);
      if (parsed == null) {
        setError("Enter a hexadecimal file offset, for example 0x200.");
        return;
      }
      const clamped =
        parsed >= BigInt(fileSize) ? BigInt(Math.max(0, fileSize - 1)) : parsed;
      setError(null);
      setAnchor(clamped);
      const row = Math.min(
        Number(clamped / BigInt(ROW_BYTES)),
        totalRows - 1,
      );
      scrollToken.current += 1;
      const element = scrollRef.current;
      if (element) {
        element.scrollTop = Math.max(0, row * ROW_HEIGHT - ROW_HEIGHT * 2);
      }
      ensureVisible();
      const address = offsetToAddress(binary.sections, clamped);
      onSelect({ address, fileOffset: formatHex(clamped) });
    },
    [binary.sections, fileSize, totalRows, virtualizer, ensureVisible, onSelect],
  );

  const stats = useMemo(() => {
    const section = currentSection;
    return {
      section: section?.name ?? null,
      address: offsetToAddress(binary.sections, anchor),
    };
  }, [binary.sections, anchor, currentSection]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-edge bg-obsidian-850 px-3 font-mono text-[10.5px] text-ink-400">
        <span className="flex items-center gap-1.5 text-ink-300">
          <Hash className="size-3.5 text-accent-400" />
          {formatHex(anchor)}
        </span>
        {stats.address && (
          <button
            className="flex items-center gap-1 text-accent-400/80 hover:text-accent-300"
            onClick={() => onNavigate({ address: stats.address }, "disassembly")}
            title="Open mapped address in disassembly"
          >
            <MoveRight className="size-3" />
            {formatHex(stats.address)}
          </button>
        )}
        <span className="text-ink-600">|</span>
        <span>{stats.section ?? "unmapped"}</span>
        <div className="flex-1" />
        <span className="text-ink-500">{totalRows.toLocaleString()} rows</span>
        <form
          className="flex items-center gap-1"
          onSubmit={(event) => {
            event.preventDefault();
            jumpTo(jumpValue);
          }}
        >
          <input
            className="input h-6 w-32 px-1.5 font-mono text-[10.5px]"
            value={jumpValue}
            onChange={(event) => setJumpValue(event.target.value)}
            spellCheck={false}
            aria-label="Go to file offset"
            placeholder="0x0"
          />
          <button className="btn h-6 px-1.5 text-[10px]" type="submit">
            Go
          </button>
        </form>
      </div>

      {error && (
        <div className="shrink-0 border-b border-red-500/20 bg-red-500/5 px-3 py-1 text-[10.5px] text-red-300/90">
          {error}
        </div>
      )}

      <div className="grid h-6 shrink-0 grid-cols-[106px_1fr_176px] items-center border-b border-edge bg-obsidian-900 px-3 font-mono text-[9.5px] uppercase tracking-wider text-ink-500 select-none">
        <span>Offset</span>
        <span>00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F</span>
        <span>ASCII</span>
      </div>

      <div
        ref={scrollRef}
        className="min-h-0 flex-1 overflow-auto"
        onScroll={handleScroll}
      >
        <div
          className="relative w-full"
          style={{ height: `${virtualizer.getTotalSize()}px` }}
        >
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const rowOffset = BigInt(virtualRow.index * ROW_BYTES);
            const withinChunk =
              virtualRow.index % CHUNK_ROWS;
            const chunkIndex = Math.floor(virtualRow.index / CHUNK_ROWS);
            const chunk = chunksRef.current.get(chunkIndex);
            const rowStart = withinChunk * ROW_BYTES;
            const bytes = chunk
              ? chunk.slice(rowStart, rowStart + ROW_BYTES)
              : null;
            const address = offsetToAddress(binary.sections, rowOffset);
            const rowSelected =
              selectedOffset != null &&
              parseHex(selectedOffset) != null &&
              (() => {
                const targetOffset = parseHex(selectedOffset)!;
                return (
                  targetOffset >= rowOffset &&
                  targetOffset < rowOffset + BigInt(ROW_BYTES)
                );
              })();

            return (
              <div
                key={virtualRow.key}
                className={`absolute left-0 top-0 grid h-[22px] w-full grid-cols-[106px_1fr_176px] items-center border-l-2 px-3 font-mono text-[11px] transition-colors ${
                  rowSelected
                    ? "border-accent-400 bg-accent-500/10"
                    : "border-transparent hover:bg-obsidian-850/70"
                }`}
                style={{ transform: `translateY(${virtualRow.start}px)` }}
                onClick={() => {
                  onSelect({
                    address,
                    fileOffset: formatHex(rowOffset),
                  });
                }}
              >
                <span className="flex items-center gap-1 text-ink-500">
                  {rowSelected ? (
                    <CornerDownRight className="size-3 shrink-0 text-accent-400" />
                  ) : (
                    <span className="w-3 shrink-0" />
                  )}
                  <span className="text-ink-400">{formatHex(rowOffset)}</span>
                </span>
                <span className="flex items-center gap-[3px]">
                  {bytes ? (
                    Array.from(bytes).map((byte, index) => (
                      <span
                        key={index}
                        className={
                          byte === 0
                            ? "text-ink-600"
                            : isPrintable(byte)
                              ? "text-ink-200"
                              : "text-sky-300/90"
                        }
                      >
                        {byte.toString(16).toUpperCase().padStart(2, "0")}
                      </span>
                    ))
                  ) : (
                    <span className="flex items-center gap-1.5 text-[10px] text-ink-600">
                      <Loader2 className="size-3 animate-spin" />
                      loading…
                    </span>
                  )}
                </span>
                <span className="tracking-[0.08em] text-ink-400">
                  {bytes
                    ? Array.from(bytes)
                        .map((byte) => (isPrintable(byte) ? String.fromCharCode(byte) : "·"))
                        .join("")
                    : ""}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      <div className="flex h-6 shrink-0 items-center gap-3 border-t border-edge bg-obsidian-900 px-3 font-mono text-[9.5px] text-ink-500">
        <span className="flex items-center gap-1">
          <Binary className="size-3" />
          {formatHex(fileSize)} bytes on disk
        </span>
        <span className="text-ink-600">|</span>
        <span>{stats.section ?? "no section at anchor"}</span>
        <span className="text-ink-600">|</span>
        <span>
          chunk {Math.floor(Number(anchor) / CHUNK_BYTES) + 1}/{chunkCount} ·
          loaded {chunksRef.current.size}
        </span>
      </div>
    </div>
  );
}
