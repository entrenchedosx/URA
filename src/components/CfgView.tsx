import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CircleStop,
  GitFork,
  Loader2,
  Maximize2,
  Pencil,
  Play,
  RotateCcw,
  Share2,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import { errorMessage, functionCfg } from "../lib/api";
import { layoutCfg } from "../lib/cfg-layout";
import {
  addressToOffset,
  formatHex,
  normalizeAddress,
} from "../lib/format";
import type { CfgBlock, FunctionCfg } from "../lib/types";
import { useSession } from "../state/session";

const MIN_ZOOM = 0.3;
const MAX_ZOOM = 2.4;

function blockContains(block: CfgBlock, address: string | null): boolean {
  if (!address) return false;
  try {
    const value = BigInt(address);
    return (
      value >= BigInt(block.address) && value < BigInt(block.endAddress)
    );
  } catch {
    return false;
  }
}

function edgeColor(kind: string, backEdge: boolean): string {
  if (backEdge) return "#e08a95";
  if (kind === "taken") return "#e8b86b";
  if (kind === "jump") return "#68a7ff";
  return "#5a6577";
}

export function CfgView() {
  const {
    binary,
    analysis,
    analysisRunning,
    analysisProgress,
    analysisError,
    functionRevision,
    selection,
    currentFunction,
    navigate,
    setSelection,
    startAnalysis,
    cancelAnalysis,
    openXrefs,
    requestRename,
    projectPath,
  } = useSession();

  const [cfg, setCfg] = useState<FunctionCfg | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);

  const scrollRef = useRef<HTMLDivElement>(null);
  const panRef = useRef<{
    x: number;
    y: number;
    left: number;
    top: number;
  } | null>(null);

  const target =
    normalizeAddress(currentFunction?.address) ??
    normalizeAddress(selection?.address);

  useEffect(() => {
    if (!binary || !analysis || !target) {
      setCfg(null);
      setError(null);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    functionCfg(target)
      .then((result) => {
        if (!cancelled) setCfg(result);
      })
      .catch((err) => {
        if (cancelled) return;
        setCfg(null);
        setError(errorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [binary, analysis, target, functionRevision]);

  const layout = useMemo(() => layoutCfg(cfg?.blocks ?? []), [cfg]);

  const fit = useCallback(() => {
    const element = scrollRef.current;
    if (!element || layout.width <= 0 || layout.height <= 0) return;
    const scale = Math.min(
      (element.clientWidth - 28) / layout.width,
      (element.clientHeight - 28) / layout.height,
      1.2,
    );
    setZoom(Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, scale)));
    requestAnimationFrame(() => {
      element.scrollTo({ left: 0, top: 0 });
    });
  }, [layout.width, layout.height]);

  useEffect(() => {
    if (!cfg) return;
    const frame = requestAnimationFrame(fit);
    return () => cancelAnimationFrame(frame);
  }, [cfg, fit]);

  useEffect(() => {
    const element = scrollRef.current;
    if (!element) return;
    const onWheel = (event: WheelEvent) => {
      if (!event.ctrlKey && !event.metaKey) return;
      event.preventDefault();
      setZoom((value) =>
        Math.max(
          MIN_ZOOM,
          Math.min(
            MAX_ZOOM,
            value * (event.deltaY < 0 ? 1.12 : 1 / 1.12),
          ),
        ),
      );
    };
    element.addEventListener("wheel", onWheel, { passive: false });
    return () => element.removeEventListener("wheel", onWheel);
  }, [cfg]);

  const selectAddress = useCallback(
    (address: string) => {
      setSelection({
        address,
        fileOffset: binary ? addressToOffset(binary.sections, address) : null,
      });
    },
    [binary, setSelection],
  );

  const jumpTo = useCallback(
    (address: string) => {
      navigate({ address }, "disassembly");
    },
    [navigate],
  );

  if (!binary) {
    return (
      <div className="flex h-full items-center justify-center bg-obsidian-900 p-6 text-[11.5px] text-ink-500">
        Open a binary to inspect control flow.
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 bg-obsidian-900 p-6 text-center">
        {analysisRunning ? (
          <>
            <Loader2 className="size-4 animate-spin text-accent-400" />
            <div className="text-[11px] text-ink-400">
              Building function graph
              {analysisProgress
                ? ` — ${analysisProgress.functions} functions discovered`
                : "…"}
            </div>
            <button
              className="btn h-7 px-2.5 text-[11px]"
              onClick={cancelAnalysis}
            >
              <CircleStop className="size-3.5 text-red-400" />
              Cancel
            </button>
          </>
        ) : (
          <>
            <GitFork className="size-5 text-ink-600" />
            <div className="text-[11.5px] text-ink-500">
              {analysisError
                ? `Function analysis failed: ${analysisError}`
                : "Function analysis has not been run for this binary."}
            </div>
            <button
              className="btn h-7 px-2.5 text-[11px]"
              onClick={startAnalysis}
            >
              <Play className="size-3.5" />
              Analyze functions
            </button>
          </>
        )}
      </div>
    );
  }

  if (!target) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 bg-obsidian-900 p-6 text-center text-[11.5px] text-ink-500">
        <GitFork className="size-5 text-ink-600" />
        Select a function to view its control-flow graph.
      </div>
    );
  }

  return (
    <div className="view-root">
      <div className="view-toolbar">
        <GitFork className="size-3.5 shrink-0 text-accent-400" />
        <span className="max-w-[220px] truncate text-ink-200">
          {cfg?.function.name ?? "Control flow"}
        </span>
        {cfg && (
          <>
            <span className="text-ink-600">|</span>
            <span className="hidden text-ink-500 @[560px]:inline">
              {cfg.function.address}
            </span>
            <span className="text-ink-600">|</span>
            <span className="hidden text-ink-500 @[460px]:inline">
              {cfg.blocks.length}/{cfg.totalBlocks} blocks ·{" "}
              {cfg.instructionCount} instructions
            </span>
          </>
        )}
        <div className="flex-1" />
        {cfg?.truncated && (
          <span className="rounded bg-amber-500/10 px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-amber-300">
            partial
          </span>
        )}
        <button
          className="icon-btn size-6"
          title="Rename function (F2)"
          disabled={!projectPath || !cfg}
          onClick={() => requestRename(cfg?.function.address ?? target)}
        >
          <Pencil className="size-3" />
        </button>
        <button
          className="icon-btn size-6"
          title="Show references"
          disabled={!cfg}
          onClick={() => openXrefs(cfg?.function.address ?? target)}
        >
          <Share2 className="size-3" />
        </button>
        <button
          className="icon-btn size-6"
          title="Open in disassembly"
          disabled={!cfg}
          onClick={() => jumpTo(cfg?.function.address ?? target)}
        >
          <Play className="size-3" />
        </button>
        <span className="mx-1 h-4 w-px bg-edge-strong" />
        <button
          className="icon-btn size-6"
          title="Zoom out"
          onClick={() =>
            setZoom((value) => Math.max(MIN_ZOOM, value / 1.15))
          }
        >
          <ZoomOut className="size-3" />
        </button>
        <span className="w-9 text-center text-[9.5px] text-ink-500">
          {Math.round(zoom * 100)}%
        </span>
        <button
          className="icon-btn size-6"
          title="Zoom in"
          onClick={() =>
            setZoom((value) => Math.min(MAX_ZOOM, value * 1.15))
          }
        >
          <ZoomIn className="size-3" />
        </button>
        <button
          className="icon-btn size-6"
          title="Fit graph to view"
          onClick={fit}
        >
          <Maximize2 className="size-3" />
        </button>
        <button
          className="icon-btn size-6"
          title="Reset zoom to 100%"
          onClick={() => setZoom(1)}
        >
          <RotateCcw className="size-3" />
        </button>
      </div>

      {loading && (
        <div className="flex flex-1 items-center justify-center gap-2 text-[11px] text-ink-500">
          <Loader2 className="size-3.5 animate-spin text-accent-400" />
          Building control-flow graph…
        </div>
      )}

      {!loading && error && (
        <div className="m-3 rounded-md border border-red-500/25 bg-red-500/5 p-3 font-mono text-[11px] text-red-300/90">
          {error}
        </div>
      )}

      {!loading && !error && cfg && (
        <div
          ref={scrollRef}
          className="relative min-h-0 flex-1 cursor-grab overflow-auto bg-obsidian-950/60 select-none active:cursor-grabbing"
          onPointerDown={(event) => {
            if ((event.target as HTMLElement).closest("[data-cfg-node]")) return;
            const element = scrollRef.current;
            if (!element) return;
            panRef.current = {
              x: event.clientX,
              y: event.clientY,
              left: element.scrollLeft,
              top: element.scrollTop,
            };
            element.setPointerCapture(event.pointerId);
          }}
          onPointerMove={(event) => {
            const element = scrollRef.current;
            const pan = panRef.current;
            if (!element || !pan) return;
            element.scrollLeft = pan.left - (event.clientX - pan.x);
            element.scrollTop = pan.top - (event.clientY - pan.y);
          }}
          onPointerUp={(event) => {
            panRef.current = null;
            const element = scrollRef.current;
            if (element?.hasPointerCapture(event.pointerId)) {
              element.releasePointerCapture(event.pointerId);
            }
          }}
          onPointerCancel={() => {
            panRef.current = null;
          }}
        >
          <div
            className="relative"
            style={{
              width: `${layout.width * zoom}px`,
              height: `${layout.height * zoom}px`,
            }}
          >
            <div
              className="absolute top-0 left-0 origin-top-left"
              style={{
                width: `${layout.width}px`,
                height: `${layout.height}px`,
                transform: `scale(${zoom})`,
              }}
            >
              <svg
                className="pointer-events-none absolute inset-0 overflow-visible"
                width={layout.width}
                height={layout.height}
                aria-hidden="true"
              >
                <defs>
                  {["fallthrough", "taken", "back", "jump"].map((kind) => (
                    <marker
                      key={kind}
                      id={`cfg-arrow-${kind}`}
                      markerWidth="7"
                      markerHeight="7"
                      refX="6"
                      refY="3.5"
                      orient="auto"
                    >
                      <path
                        d="M 0 0 L 7 3.5 L 0 7 z"
                        fill={
                          kind === "back"
                            ? "#e08a95"
                            : kind === "taken"
                              ? "#e8b86b"
                              : kind === "jump"
                                ? "#68a7ff"
                                : "#5a6577"
                        }
                      />
                    </marker>
                  ))}
                </defs>
                {layout.edges.map((edge, index) => {
                  const color = edgeColor(edge.edge.kind, edge.backEdge);
                  const marker = edge.backEdge
                    ? "back"
                    : edge.edge.kind === "taken"
                      ? "taken"
                      : edge.edge.kind === "jump"
                        ? "jump"
                        : "fallthrough";
                  return (
                    <path
                      key={`${edge.from.block.address}-${edge.to.block.address}-${index}`}
                      d={edge.path}
                      fill="none"
                      stroke={color}
                      strokeWidth={edge.backEdge ? 1.4 : 1.6}
                      strokeDasharray={edge.backEdge ? "5 4" : undefined}
                      markerEnd={`url(#cfg-arrow-${marker})`}
                      opacity={0.85}
                    />
                  );
                })}
              </svg>

              {layout.nodes.map((node) => {
                const block = node.block;
                const active = blockContains(
                  block,
                  normalizeAddress(selection?.address),
                );
                const entry = cfg.blocks[0]?.address === block.address;
                return (
                  <div
                    key={block.address}
                    data-cfg-node
                    className={`absolute overflow-hidden rounded-md border bg-obsidian-850 shadow-[0_6px_20px_rgba(0,0,0,0.35)] transition-colors ${
                      active
                        ? "border-accent-400/80 ring-1 ring-accent-400/25"
                        : "border-edge-strong hover:border-ink-600"
                    }`}
                    style={{
                      left: `${node.x}px`,
                      top: `${node.y}px`,
                      width: `${node.width}px`,
                      minHeight: `${node.height}px`,
                    }}
                    onDoubleClick={() => jumpTo(block.address)}
                  >
                    <button
                      className={`flex h-[28px] w-full items-center gap-1.5 border-b px-2 text-left ${
                        entry
                          ? "border-accent-500/25 bg-accent-500/10"
                          : "border-edge bg-obsidian-800"
                      }`}
                      onClick={() => selectAddress(block.address)}
                      title={`Block ${block.address} → ${block.endAddress} · double-click to disassemble`}
                    >
                      <span className="font-mono text-[10px] text-ink-300">
                        {formatHex(block.address)}
                      </span>
                      {entry && (
                        <span className="rounded bg-accent-500/20 px-1 text-[8px] uppercase tracking-wide text-accent-300">
                          entry
                        </span>
                      )}
                      <span className="flex-1" />
                      <span className="font-mono text-[8.5px] text-ink-600">
                        {block.instructionCount} insn
                      </span>
                    </button>
                    <div className="py-[7px]">
                      {block.lines.map((line) => {
                        const lineAddress = normalizeAddress(line.address);
                        const lineActive =
                          lineAddress != null &&
                          lineAddress === normalizeAddress(selection?.address);
                        return (
                          <button
                            key={line.address}
                            className={`grid h-[18px] w-full grid-cols-[82px_minmax(0,1fr)] items-center gap-1 px-2 text-left font-mono text-[10.5px] transition-colors ${
                              lineActive
                                ? "bg-accent-500/15 text-accent-200"
                                : "text-ink-300 hover:bg-obsidian-750"
                            }`}
                            onClick={() => selectAddress(line.address)}
                            onDoubleClick={(event) => {
                              event.stopPropagation();
                              jumpTo(line.address);
                            }}
                            title={`${line.address} · ${line.text}${
                              line.targetName ? ` → ${line.targetName}` : ""
                            }`}
                          >
                            <span className="truncate text-ink-500">
                              {formatHex(line.address)}
                            </span>
                            <span className="flex min-w-0 items-center gap-1">
                              <span className="truncate">{line.text}</span>
                              {line.targetName && (
                                <span className="max-w-[82px] shrink-0 truncate text-[9px] text-accent-400/80">
                                  {line.targetName}
                                </span>
                              )}
                            </span>
                          </button>
                        );
                      })}
                      {block.omittedInstructions > 0 && (
                        <div className="px-2 font-mono text-[9px] text-ink-600">
                          … {block.omittedInstructions} more instructions
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {!loading && !error && cfg && (
        <div className="flex h-6 shrink-0 items-center gap-3 border-t border-edge bg-obsidian-850 px-2.5 font-mono text-[9px] text-ink-600">
          <span className="flex items-center gap-1">
            <span className="inline-block size-0.5 rounded-full bg-accent-400" />
            jump
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block size-0.5 rounded-full bg-amber-400" />
            taken
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block size-0.5 rounded-full bg-rose-400" />
            back edge
          </span>
          <span className="ml-auto hidden @[460px]:inline">
            Ctrl+wheel to zoom · drag to pan
          </span>
        </div>
      )}
    </div>
  );
}
