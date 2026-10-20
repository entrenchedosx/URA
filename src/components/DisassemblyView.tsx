import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  AlertTriangle,
  ArrowDownToLine,
  BookMarked,
  CornerDownRight,
  Cpu,
  Loader2,
  RefreshCw,
  TriangleAlert,
} from "lucide-react";
import { disassemble, errorMessage } from "../lib/api";
import {
  formatHex,
  normalizeAddress,
  parseHex,
  sectionForAddress,
} from "../lib/format";
import type {
  Annotation,
  BinaryOpenResult,
  InstructionView,
  NavigateFn,
  NavigationTarget,
  Selection,
} from "../lib/types";

const PAGE_SIZE = 320;

interface DisassemblyViewProps {
  binary: BinaryOpenResult;
  target: NavigationTarget;
  selection: Selection | null;
  annotations: Annotation[];
  onSelect: (selection: Selection) => void;
  onNavigate: NavigateFn;
  onLog: (level: "info" | "success" | "warning" | "error", text: string) => void;
}

export function DisassemblyView({
  binary,
  target,
  selection,
  annotations,
  onSelect,
  onNavigate,
  onLog,
}: DisassemblyViewProps) {
  const [instructions, setInstructions] = useState<InstructionView[]>([]);
  const [sectionName, setSectionName] = useState<string>("");
  const [architecture, setArchitecture] = useState<string>("");
  const [warnings, setWarnings] = useState<string[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const scrollRef = useRef<HTMLDivElement>(null);
  const requestId = useRef(0);
  const animationFrame = useRef<number | null>(null);

  const supported =
    binary.info.architecture === "x86" || binary.info.architecture === "x86-64";

  const annotationMap = useMemo(() => {
    const map = new Map<string, Annotation>();
    for (const annotation of annotations) {
      const address = normalizeAddress(annotation.address);
      if (address) map.set(address, annotation);
    }
    return map;
  }, [annotations]);

  const loadInitial = useCallback(
    (address: string) => {
      const current = ++requestId.current;
      setLoading(true);
      setError(null);
      setInstructions([]);
      setWarnings([]);
      setHasMore(false);
      disassemble(address, PAGE_SIZE)
        .then((page) => {
          if (current !== requestId.current) return;
          setInstructions(page.instructions);
          setSectionName(page.section);
          setArchitecture(page.architecture);
          setWarnings(page.warnings);
          setHasMore(page.hasMore);
        })
        .catch((err) => {
          if (current !== requestId.current) return;
          setError(errorMessage(err));
          onLog("error", `Disassembly failed at ${address}: ${errorMessage(err)}`);
        })
        .finally(() => {
          if (current === requestId.current) setLoading(false);
        });
    },
    [onLog],
  );

  useEffect(() => {
    if (!supported) {
      setError(`Disassembly is not available for ${binary.info.architecture}.`);
      return;
    }
    const address = target.address ?? binary.info.entryPoint;
    if (!address) {
      setError("This binary does not expose an entry point.");
      return;
    }
    loadInitial(normalizeAddress(address) ?? address);
    if (animationFrame.current != null) cancelAnimationFrame(animationFrame.current);
    animationFrame.current = requestAnimationFrame(() => {
      scrollRef.current?.scrollTo({ top: 0 });
    });
  }, [target.nonce, refreshKey, binary, supported, loadInitial, target.address]);

  const loadMore = useCallback(() => {
    if (!hasMore || loadingMore || loading || instructions.length === 0) return;
    const last = instructions[instructions.length - 1];
    const lastAddress = parseHex(last.address);
    if (lastAddress == null) return;
    const nextAddress = formatHex(lastAddress + BigInt(last.length));
    const current = requestId.current;
    setLoadingMore(true);
    disassemble(nextAddress, PAGE_SIZE)
      .then((page) => {
        if (current !== requestId.current) return;
        setInstructions((previous) => {
          if (page.instructions.length === 0) return previous;
          const trailing = page.instructions[page.instructions.length - 1];
          const previousLast = previous[previous.length - 1];
          if (
            previousLast &&
            normalizeAddress(previousLast.address) ===
              normalizeAddress(trailing.address) &&
            previousLast.length === trailing.length
          ) {
            setHasMore(false);
            return previous;
          }
          return [...previous, ...page.instructions];
        });
        setHasMore(page.hasMore);
        if (page.warnings.length > 0) {
          setWarnings((previous) =>
            Array.from(new Set([...previous, ...page.warnings])),
          );
        }
      })
      .catch((err) => {
        if (current !== requestId.current) return;
        setHasMore(false);
        onLog("warning", `Unable to continue disassembly: ${errorMessage(err)}`);
      })
      .finally(() => {
        if (current === requestId.current) setLoadingMore(false);
      });
  }, [hasMore, loadingMore, loading, instructions, onLog]);

  const virtualizer = useVirtualizer({
    count: instructions.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 24,
    overscan: 24,
  });

  const selectedIndex = useMemo(() => {
    if (!selection?.address) return -1;
    const wanted = normalizeAddress(selection.address);
    return instructions.findIndex(
      (instruction) => normalizeAddress(instruction.address) === wanted,
    );
  }, [instructions, selection?.address]);

  const selectInstruction = useCallback(
    (instruction: InstructionView) => {
      onSelect({
        address: instruction.address,
        fileOffset: instruction.fileOffset,
        mnemonic: instruction.mnemonic,
        text: instruction.text,
        bytes: instruction.bytes,
      });
    },
    [onSelect],
  );

  const moveSelection = useCallback(
    (delta: number) => {
      if (instructions.length === 0) return;
      let index = selectedIndex;
      if (index < 0) index = 0;
      else index = Math.min(instructions.length - 1, Math.max(0, index + delta));
      const instruction = instructions[index];
      selectInstruction(instruction);
      virtualizer.scrollToIndex(index, { align: "auto" });
      if (index >= instructions.length - 8) loadMore();
    },
    [instructions, selectedIndex, selectInstruction, virtualizer, loadMore],
  );

  const handleScroll = useCallback(() => {
    const element = scrollRef.current;
    if (!element) return;
    if (element.scrollTop + element.clientHeight >= element.scrollHeight - 320) {
      loadMore();
    }
  }, [loadMore]);

  const startAddress =
    instructions.length > 0 ? instructions[0].address : target.address ?? null;
  const endAddress =
    instructions.length > 0
      ? formatHex(
          BigInt(instructions[instructions.length - 1].address) +
            BigInt(instructions[instructions.length - 1].length),
        )
      : null;

  if (!supported) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <div className="max-w-md rounded-lg border border-amber-500/25 bg-amber-500/5 p-5 text-center">
          <TriangleAlert className="mx-auto mb-2 size-6 text-amber-400" />
          <div className="text-[13px] font-medium text-amber-200">
            Disassembly is not available for {binary.info.architecture}
          </div>
          <div className="mt-1 text-[11.5px] leading-relaxed text-ink-400">
            v0.1 decodes x86 and x86-64 through iced-x86. Sections, symbols, hex
            and strings remain available for this image.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-3 border-b border-edge bg-obsidian-850 px-3 font-mono text-[10.5px] text-ink-400">
        <span className="flex items-center gap-1.5 text-ink-300">
          <Cpu className="size-3.5 text-accent-400" />
          {sectionName || "—"}
        </span>
        <span className="text-ink-600">|</span>
        <span>{architecture || binary.info.architecture}</span>
        <span className="text-ink-600">|</span>
        <span className="text-ink-500">
          {startAddress ? formatHex(startAddress) : "—"}
          {endAddress ? ` → ${formatHex(endAddress)}` : ""}
        </span>
        <div className="flex-1" />
        <span className="text-ink-500">{instructions.length} loaded</span>
        <button
          className="icon-btn size-6"
          onClick={() => setRefreshKey((value) => value + 1)}
          title="Reload disassembly at current start"
          aria-label="Reload disassembly"
        >
          <RefreshCw className="size-3" />
        </button>
      </div>

      {warnings.length > 0 && (
        <div className="flex shrink-0 items-center gap-2 border-b border-amber-500/20 bg-amber-500/5 px-3 py-1 text-[10.5px] text-amber-300/90">
          <AlertTriangle className="size-3 shrink-0" />
          <span className="truncate">{warnings.join(" · ")}</span>
        </div>
      )}

      <div className="grid h-6 shrink-0 grid-cols-[112px_188px_66px_1fr_120px] items-center border-b border-edge bg-obsidian-900 px-3 font-mono text-[9.5px] uppercase tracking-wider text-ink-500 select-none">
        <span>Address</span>
        <span>Bytes</span>
        <span>Mnemonic</span>
        <span>Operands</span>
        <span className="text-right">Target / Note</span>
      </div>

      <div
        ref={scrollRef}
        className="min-h-0 flex-1 overflow-auto outline-none"
        onScroll={handleScroll}
        tabIndex={0}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown") {
            event.preventDefault();
            moveSelection(1);
          } else if (event.key === "ArrowUp") {
            event.preventDefault();
            moveSelection(-1);
          } else if (event.key === "PageDown") {
            event.preventDefault();
            moveSelection(20);
          } else if (event.key === "PageUp") {
            event.preventDefault();
            moveSelection(-20);
          }
        }}
      >
        {loading && instructions.length === 0 && (
          <div className="flex h-40 items-center justify-center gap-2 text-[11.5px] text-ink-500">
            <Loader2 className="size-4 animate-spin text-accent-400" />
            Decoding instructions…
          </div>
        )}

        {error && instructions.length === 0 && (
          <div className="m-3 rounded-md border border-red-500/25 bg-red-500/5 p-3 font-mono text-[11px] text-red-300/90">
            {error}
          </div>
        )}

        {!loading && !error && instructions.length === 0 && (
          <div className="p-4 text-[11.5px] text-ink-500">
            No instructions decoded at this address.
          </div>
        )}

        <div
          className="relative w-full"
          style={{ height: `${virtualizer.getTotalSize()}px` }}
        >
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const instruction = instructions[virtualRow.index];
            const address = normalizeAddress(instruction.address);
            const annotation = address ? annotationMap.get(address) : undefined;
            const selected = virtualRow.index === selectedIndex;
            const targetValue = instruction.target
              ? normalizeAddress(instruction.target)
              : null;
            const instructionSection = sectionForAddress(
              binary.sections,
              instruction.address,
            );
            const targetSection = targetValue
              ? sectionForAddress(binary.sections, targetValue)
              : null;

            return (
              <div
                key={virtualRow.key}
                className={`absolute left-0 top-0 grid h-6 w-full grid-cols-[112px_188px_66px_1fr_120px] items-center border-l-2 px-3 font-mono text-[11.5px] transition-colors ${
                  selected
                    ? "border-accent-400 bg-accent-500/12"
                    : "border-transparent hover:bg-obsidian-850/80"
                } ${instruction.invalid ? "text-red-300/80" : ""}`}
                style={{ transform: `translateY(${virtualRow.start}px)` }}
                onClick={() => selectInstruction(instruction)}
              >
                <span className="flex items-center gap-1 text-ink-500">
                  {selected ? (
                    <CornerDownRight className="size-3 shrink-0 text-accent-400" />
                  ) : (
                    <span className="w-3 shrink-0" />
                  )}
                  <span className="text-ink-400">{formatHex(instruction.address)}</span>
                </span>
                <span
                  className="truncate text-ink-600"
                  title={instruction.fileOffset ?? undefined}
                >
                  {instruction.bytes}
                </span>
                <span
                  className={
                    instruction.invalid
                      ? "text-red-400"
                      : instruction.flow.includes("call")
                        ? "text-emerald-400"
                        : instruction.flow.includes("jump")
                          ? "text-accent-300"
                          : instruction.flow === "return"
                            ? "text-rose-400"
                            : instruction.privileged
                              ? "text-amber-400"
                              : "text-sky-300"
                  }
                >
                  {instruction.mnemonic}
                </span>
                <span className="flex min-w-0 items-center gap-2 pr-2 text-ink-200">
                  <span className="truncate">{instruction.operands}</span>
                  {annotation && (
                    <span className="flex shrink-0 items-center gap-1 rounded bg-amber-500/10 px-1 text-[9.5px] text-amber-300">
                      <BookMarked className="size-2.5" />
                      {annotation.label ?? "note"}
                    </span>
                  )}
                </span>
                <span className="flex justify-end">
                  {targetValue && (
                    <button
                      className="flex items-center gap-1 rounded px-1 font-mono text-[10px] text-accent-400/80 hover:bg-accent-500/10 hover:text-accent-300"
                      onClick={(event) => {
                        event.stopPropagation();
                        if (targetSection?.executable) {
                          onNavigate({ address: targetValue }, "disassembly");
                        } else {
                          onNavigate({ address: targetValue }, "hex");
                        }
                      }}
                      title={`Follow branch to ${targetValue} (${targetSection?.name ?? "unmapped"})`}
                    >
                      <ArrowDownToLine className="size-2.5 -rotate-90" />
                      {formatHex(targetValue)}
                    </button>
                  )}
                </span>
                {instructionSection && !targetValue && (
                  <span className="pointer-events-none absolute right-3 font-mono text-[9px] text-ink-600">
                    {instructionSection.name}
                  </span>
                )}
              </div>
            );
          })}
        </div>

        {loadingMore && (
          <div className="flex items-center justify-center gap-2 py-2 text-[10.5px] text-ink-500">
            <Loader2 className="size-3 animate-spin" />
            Decoding next page…
          </div>
        )}

        {!hasMore && instructions.length > 0 && (
          <div className="py-2 text-center font-mono text-[9.5px] uppercase tracking-wider text-ink-600">
            end of section · {instructions.length} instructions decoded
          </div>
        )}
      </div>
    </div>
  );
}
