import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  Binary,
  Clipboard,
  CornerDownRight,
  Hash,
  Loader2,
  MoveRight,
} from "lucide-react";
import { errorMessage, readHex } from "../lib/api";
import {
  addressToOffset,
  formatHex,
  normalizeAddress,
  offsetToAddress,
  parseHex,
  sectionForOffset,
} from "../lib/format";
import { useMessages } from "../state/messages";
import { useSession } from "../state/session";
import { rowHeightFor, useSettings } from "../state/settings";
import { useWorkspace } from "../state/workspace";
import { ContextMenu, type ContextMenuItem } from "./ContextMenu";

const CHUNK_BYTES = 8192;

function isPrintable(byte: number): boolean {
  return byte >= 0x20 && byte <= 0x7e;
}

export function HexView() {
  const { binary, navigation: target, selection, setSelection, navigate } =
    useSession();
  const { log } = useMessages();
  const { settings } = useSettings();
  const workspace = useWorkspace();

  const [bytesPerRow, setBytesPerRow] = useState(16);
  const [anchor, setAnchor] = useState<bigint>(0n);
  const [jumpValue, setJumpValue] = useState("");
  const [, setChunkVersion] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [menu, setMenu] = useState<{
    x: number;
    y: number;
    rowOffset: bigint;
    rowBytes: Uint8Array | null;
    byteIndex: number | null;
  } | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const chunksRef = useRef<Map<number, Uint8Array>>(new Map());
  const pendingRef = useRef<Set<number>>(new Set());
  const rafRef = useRef<number | null>(null);
  const scrollToken = useRef(0);

  const fileSize = binary?.info.fileSize ?? 0;
  const rowHeight = rowHeightFor(settings);
  const totalRows = Math.max(1, Math.ceil(fileSize / bytesPerRow));
  const rowsPerChunk = Math.max(1, Math.floor(CHUNK_BYTES / bytesPerRow));
  const chunkCount = Math.max(1, Math.ceil(totalRows / rowsPerChunk));

  const virtualizer = useVirtualizer({
    count: totalRows,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: 32,
  });

  useEffect(() => {
    virtualizer.measure();
  }, [rowHeight, virtualizer]);

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
          log(
            "error",
            `Hex read failed at ${formatHex(offset)}: ${errorMessage(err)}`,
          );
        });
    },
    [chunkCount, fileSize, log],
  );

  const ensureVisible = useCallback(() => {
    const element = scrollRef.current;
    if (!element) return;
    const firstRow = Math.max(0, Math.floor(element.scrollTop / rowHeight) - 2);
    const lastRow = Math.min(
      totalRows - 1,
      Math.ceil((element.scrollTop + element.clientHeight) / rowHeight) + 2,
    );
    const firstChunk = Math.floor(firstRow / rowsPerChunk);
    const lastChunk = Math.floor(lastRow / rowsPerChunk);
    for (let index = firstChunk; index <= lastChunk; index += 1) {
      loadChunk(index);
    }
  }, [loadChunk, totalRows, rowHeight, rowsPerChunk]);

  const handleScroll = useCallback(() => {
    if (rafRef.current != null) return;
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = null;
      ensureVisible();
      const element = scrollRef.current;
      if (element) {
        const row = Math.floor(element.scrollTop / rowHeight);
        setAnchor(BigInt(row * bytesPerRow));
      }
    });
  }, [ensureVisible, rowHeight, bytesPerRow]);

  const scrollToOffset = useCallback(
    (offsetValue: bigint) => {
      const row = Math.min(
        Math.max(0, Number(offsetValue / BigInt(bytesPerRow))),
        totalRows - 1,
      );
      const element = scrollRef.current;
      if (element) {
        element.scrollTop = Math.max(0, row * rowHeight - rowHeight * 2);
      }
      ensureVisible();
    },
    [bytesPerRow, totalRows, rowHeight, ensureVisible],
  );

  useEffect(() => {
    if (!binary) return;
    const offsetValue =
      parseHex(target.fileOffset) ??
      (target.address
        ? parseHex(addressToOffset(binary.sections, target.address))
        : null) ??
      0n;
    const clamped =
      offsetValue < 0n
        ? 0n
        : offsetValue >= BigInt(fileSize)
          ? BigInt(Math.max(0, fileSize - 1))
          : offsetValue;
    setAnchor(clamped);
    setJumpValue(formatHex(clamped));
    scrollToken.current += 1;
    const token = scrollToken.current;
    const applyScroll = () => {
      if (scrollToken.current !== token) return;
      scrollToOffset(clamped);
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
  }, [target.nonce, target.address, target.fileOffset, bytesPerRow]);

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
  const selectedAnchor = useMemo(() => {
    if (!binary) return null;
    if (selectedOffset) return parseHex(selectedOffset);
    if (selection?.address) {
      return parseHex(addressToOffset(binary.sections, selection.address));
    }
    return null;
  }, [binary, selectedOffset, selection?.address]);
  const focusOffset = selectedAnchor ?? anchor;
  const currentSection = binary
    ? sectionForOffset(binary.sections, focusOffset)
    : null;

  const jumpTo = useCallback(
    (raw: string) => {
      if (!binary) return;
      const parsed = parseHex(raw);
      if (parsed == null) {
        setError("Enter a hexadecimal file offset, for example 0x200.");
        return;
      }
      const clamped =
        parsed >= BigInt(fileSize) ? BigInt(Math.max(0, fileSize - 1)) : parsed;
      setError(null);
      setAnchor(clamped);
      scrollToken.current += 1;
      scrollToOffset(clamped);
      const address = offsetToAddress(binary.sections, clamped);
      setSelection({ address, fileOffset: formatHex(clamped) });
    },
    [binary, fileSize, scrollToOffset, setSelection],
  );

  const stats = useMemo(() => {
    if (!binary) return { section: null, address: null };
    return {
      section: currentSection?.name ?? null,
      address: offsetToAddress(binary.sections, focusOffset),
    };
  }, [binary, focusOffset, currentSection]);

  const copy = useCallback(
    (text: string, label: string) => {
      navigator.clipboard.writeText(text).catch((err) => {
        log("warning", `Unable to copy ${label}: ${errorMessage(err)}`);
      });
    },
    [log],
  );

  const menuItems: ContextMenuItem[] = useMemo(() => {
    if (!menu || !binary) return [];
    const offset = menu.rowOffset + BigInt(menu.byteIndex ?? 0);
    const address = offsetToAddress(binary.sections, offset);
    const bytes = menu.rowBytes;
    const hex = bytes
      ? Array.from(bytes)
          .map((byte) => byte.toString(16).toUpperCase().padStart(2, "0"))
          .join(" ")
      : "";
    const ascii = bytes
      ? Array.from(bytes)
          .map((byte) => (isPrintable(byte) ? String.fromCharCode(byte) : "."))
          .join("")
      : "";
    const items: ContextMenuItem[] = [
      {
        label: "Copy offset",
        icon: Clipboard,
        onSelect: () => copy(formatHex(offset), "offset"),
      },
      {
        label: "Copy row hex",
        icon: Clipboard,
        disabled: !hex,
        onSelect: () => copy(hex, "hex bytes"),
      },
      {
        label: "Copy row ASCII",
        icon: Clipboard,
        disabled: !ascii,
        onSelect: () => copy(ascii, "ASCII"),
      },
    ];
    if (address) {
      items.push(
        { label: "-", onSelect: () => undefined },
        {
          label: "Open address in disassembly",
          icon: MoveRight,
          onSelect: () => navigate({ address }, "disassembly"),
        },
        {
          label: "Annotate this address",
          icon: Hash,
          onSelect: () => {
            setSelection({ address, fileOffset: formatHex(offset) });
            workspace.showPanel("inspector");
          },
        },
      );
    }
    return items;
  }, [menu, binary, copy, navigate, setSelection, workspace]);

  if (!binary) {
    return (
      <div className="flex h-full items-center justify-center bg-obsidian-900 p-6 text-[11.5px] text-ink-500">
        Open a binary to inspect raw bytes.
      </div>
    );
  }

  return (
    <div className="view-root">
      <div className="view-toolbar">
        <span className="flex items-center gap-1.5 text-ink-300">
          <Hash className="size-3.5 text-accent-400" />
          {formatHex(focusOffset)}
        </span>
        {stats.address && (
          <button
            className="flex items-center gap-1 text-accent-400/80 hover:text-accent-300"
            onClick={() => navigate({ address: stats.address }, "disassembly")}
            title="Open mapped address in disassembly"
          >
            <MoveRight className="size-3" />
            {formatHex(stats.address)}
          </button>
        )}
        <span className="text-ink-600">|</span>
        <span className="truncate">{stats.section ?? "unmapped"}</span>
        <div className="flex-1" />
        <label className="flex items-center gap-1 text-ink-500">
          <span className="text-[9.5px] uppercase tracking-wider">Row</span>
          <select
            className="h-6 rounded border border-edge-strong bg-obsidian-800 px-1 font-mono text-[10px] text-ink-300 focus:outline-none"
            value={bytesPerRow}
            onChange={(event) => {
              const next = Number(event.target.value);
              setBytesPerRow(next);
              chunksRef.current.clear();
              pendingRef.current.clear();
              setChunkVersion((value) => value + 1);
              requestAnimationFrame(() => {
                scrollToOffset(anchor);
                ensureVisible();
              });
            }}
            aria-label="Bytes per row"
          >
            <option value={8}>8 bytes</option>
            <option value={16}>16 bytes</option>
            <option value={32}>32 bytes</option>
          </select>
        </label>
        <span className="text-ink-500">{totalRows.toLocaleString()} rows</span>
        <form
          className="flex items-center gap-1"
          onSubmit={(event) => {
            event.preventDefault();
            jumpTo(jumpValue);
          }}
        >
          <input
            className="input h-6 w-28 px-1.5 font-mono text-[10.5px]"
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

      <div className="view-columns hex-grid">
        <span>Offset</span>
        <span className="hex-bytes" style={{ ["--hex-cols" as string]: bytesPerRow }}>
          {Array.from({ length: bytesPerRow }, (_, index) => (
            <span key={index} className="text-center">
              {index.toString(16).toUpperCase().padStart(2, "0")}
            </span>
          ))}
        </span>
        <span className="hex-ascii-col">ASCII</span>
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
            const rowOffset = BigInt(virtualRow.index * bytesPerRow);
            const withinChunk = virtualRow.index % rowsPerChunk;
            const chunkIndex = Math.floor(virtualRow.index / rowsPerChunk);
            const chunk = chunksRef.current.get(chunkIndex);
            const rowStart = withinChunk * bytesPerRow;
            const bytes = chunk
              ? chunk.slice(rowStart, rowStart + bytesPerRow)
              : null;
            const address = offsetToAddress(binary.sections, rowOffset);
            const targetOffset = selectedOffset ? parseHex(selectedOffset) : null;
            const rowSelected =
              targetOffset != null &&
              targetOffset >= rowOffset &&
              targetOffset < rowOffset + BigInt(bytesPerRow);
            const selectedIndexInRow =
              rowSelected && targetOffset != null
                ? Number(targetOffset - rowOffset)
                : -1;

            return (
              <div
                key={virtualRow.key}
                className={`hex-row hex-grid items-center border-l-2 font-mono transition-colors ${
                  rowSelected
                    ? "border-accent-400 bg-accent-500/10"
                    : "border-transparent hover:bg-obsidian-850/70"
                }`}
                style={{
                  transform: `translateY(${virtualRow.start}px)`,
                  height: rowHeight,
                  fontSize: settings.codeFontSize,
                }}
                onClick={() =>
                  setSelection({
                    address,
                    fileOffset: formatHex(rowOffset),
                  })
                }
                onContextMenu={(event) => {
                  event.preventDefault();
                  setMenu({
                    x: event.clientX,
                    y: event.clientY,
                    rowOffset,
                    rowBytes: bytes,
                    byteIndex: null,
                  });
                }}
              >
                <span className="flex min-w-0 items-center gap-1 text-ink-500">
                  {rowSelected ? (
                    <CornerDownRight className="size-3 shrink-0 text-accent-400" />
                  ) : (
                    <span className="w-3 shrink-0" />
                  )}
                  <span className="truncate text-ink-400">
                    {formatHex(rowOffset)}
                  </span>
                </span>
                <span
                  className="hex-bytes min-w-0"
                  style={{ ["--hex-cols" as string]: bytesPerRow }}
                >
                  {bytes ? (
                    Array.from(bytes).map((byte, index) => (
                      <span
                        key={index}
                        className={`hex-byte ${
                          selectedIndexInRow === index ? "selected" : ""
                        } ${
                          byte === 0
                            ? "text-ink-600"
                            : isPrintable(byte)
                              ? "text-ink-200"
                              : "text-sky-300/90"
                        }`}
                        style={{
                          marginLeft:
                            index > 0 && index % 4 === 0 ? "3px" : undefined,
                        }}
                        onClick={(event) => {
                          event.stopPropagation();
                          const offset = rowOffset + BigInt(index);
                          setSelection({
                            address: offsetToAddress(binary.sections, offset),
                            fileOffset: formatHex(offset),
                          });
                        }}
                        onContextMenu={(event) => {
                          event.preventDefault();
                          event.stopPropagation();
                          setMenu({
                            x: event.clientX,
                            y: event.clientY,
                            rowOffset,
                            rowBytes: bytes,
                            byteIndex: index,
                          });
                        }}
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
                <span className="hex-ascii-col truncate tracking-[0.06em] text-ink-400">
                  {bytes
                    ? Array.from(bytes).map((byte, index) => (
                        <span
                          key={index}
                          className={
                            selectedIndexInRow === index
                              ? "rounded bg-accent-500/25 text-ink-100"
                              : ""
                          }
                        >
                          {isPrintable(byte) ? String.fromCharCode(byte) : "·"}
                        </span>
                      ))
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
        <span className="hex-footer-extra text-ink-600">|</span>
        <span className="hex-footer-extra">
          {bytesPerRow} bytes/row · chunk{" "}
          {Math.floor(Number(anchor) / CHUNK_BYTES) + 1}/{chunkCount} · loaded{" "}
          {chunksRef.current.size}
        </span>
        <div className="flex-1" />
        <span className="hex-footer-help text-ink-600">
          click a byte to select · right-click for actions
        </span>
      </div>

      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          items={menuItems}
          onClose={() => setMenu(null)}
        />
      )}
    </div>
  );
}
