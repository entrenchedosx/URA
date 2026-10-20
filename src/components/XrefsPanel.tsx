import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Crosshair,
  Loader2,
  MoveRight,
  Play,
  RefreshCw,
  Share2,
} from "lucide-react";
import { errorMessage, xrefsFrom, xrefsTo } from "../lib/api";
import {
  formatHex,
  normalizeAddress,
  sectionForAddress,
} from "../lib/format";
import type { XrefView } from "../lib/types";
import { useSession } from "../state/session";

type Scope = "function" | "address";
type Direction = "incoming" | "outgoing";

const kindLabels: Record<string, string> = {
  call: "call",
  jump: "jump",
  conditionalJump: "cond",
  data: "data",
};

function kindClass(kind: string): string {
  if (kind === "call") return "bg-emerald-500/10 text-emerald-300";
  if (kind === "conditionalJump") return "bg-amber-500/10 text-amber-300";
  if (kind === "data") return "bg-teal-500/10 text-teal-300";
  return "bg-accent-500/10 text-accent-300";
}

function dataKindLabel(value: string | null): string | null {
  if (value === "ripRelative") return "RIP-relative";
  if (value === "absolute") return "absolute";
  return null;
}

export function XrefsPanel() {
  const {
    binary,
    analysis,
    analysisRunning,
    analysisError,
    functionRevision,
    selection,
    currentFunction,
    navigate,
    startAnalysis,
  } = useSession();

  const [scope, setScope] = useState<Scope>("function");
  const [direction, setDirection] = useState<Direction>("incoming");
  const [incoming, setIncoming] = useState<{
    total: number;
    references: XrefView[];
  }>({ total: 0, references: [] });
  const [outgoing, setOutgoing] = useState<{
    total: number;
    references: XrefView[];
  }>({ total: 0, references: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const functionAddress = normalizeAddress(currentFunction?.address);
  const selectionAddress = normalizeAddress(selection?.address);
  const target =
    scope === "function"
      ? functionAddress ?? selectionAddress
      : selectionAddress ?? functionAddress;

  useEffect(() => {
    if (!binary || !analysis || !target) {
      setIncoming({ total: 0, references: [] });
      setOutgoing({ total: 0, references: [] });
      setLoading(false);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([xrefsTo(target), xrefsFrom(target)])
      .then(([incomingPage, outgoingPage]) => {
        if (cancelled) return;
        setIncoming({
          total: incomingPage.total,
          references: incomingPage.references,
        });
        setOutgoing({
          total: outgoingPage.total,
          references: outgoingPage.references,
        });
      })
      .catch((err) => {
        if (!cancelled) setError(errorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [binary, analysis, target, functionRevision, refreshKey]);

  const page = direction === "incoming" ? incoming : outgoing;
  const scopeLabel = useMemo(() => {
    if (scope === "function") {
      return currentFunction?.name ?? "function";
    }
    return target ? `address ${formatHex(target)}` : "address";
  }, [scope, currentFunction?.name, target]);

  const openReference = useCallback(
    (reference: XrefView) => {
      const address =
        direction === "incoming" ? reference.from : reference.to;
      const section = binary
        ? sectionForAddress(binary.sections, address)
        : null;
      navigate(
        { address },
        section?.executable ? "disassembly" : "hex",
      );
    },
    [binary, direction, navigate],
  );

  if (!binary) {
    return (
      <div className="flex h-full items-center justify-center bg-obsidian-850 p-6 text-[11.5px] text-ink-500">
        Open a binary to inspect references.
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 bg-obsidian-850 p-6 text-center">
        <Share2 className="size-5 text-ink-600" />
        <div className="text-[11px] text-ink-500">
          {analysisRunning
            ? "Analysis is still running — references will appear when it finishes."
            : analysisError
              ? `Function analysis failed: ${analysisError}`
              : "Function analysis has not been run for this binary."}
        </div>
        {!analysisRunning && (
          <button
            className="btn h-7 px-2.5 text-[11px]"
            onClick={startAnalysis}
          >
            <Play className="size-3.5" />
            Analyze functions
          </button>
        )}
      </div>
    );
  }

  if (!target) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 bg-obsidian-850 p-6 text-center text-[11.5px] text-ink-500">
        <Crosshair className="size-5 text-ink-600" />
        Select an instruction or function to inspect references.
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-obsidian-850">
      <div className="flex h-7 shrink-0 items-center gap-1.5 border-b border-edge px-2">
        <Share2 className="size-3 text-accent-400" />
        <span className="truncate font-mono text-[9.5px] text-ink-400">
          {formatHex(target)}
        </span>
        <span className="min-w-0 flex-1 truncate text-[9.5px] text-ink-500">
          {scopeLabel}
        </span>
        <div className="flex shrink-0 overflow-hidden rounded border border-edge-strong">
          <button
            className={`h-5 px-1.5 font-mono text-[9px] ${
              scope === "function"
                ? "bg-accent-500/20 text-accent-200"
                : "text-ink-500 hover:text-ink-300"
            }`}
            onClick={() => setScope("function")}
            title="References to the containing function"
          >
            fn
          </button>
          <button
            className={`h-5 px-1.5 font-mono text-[9px] ${
              scope === "address"
                ? "bg-accent-500/20 text-accent-200"
                : "text-ink-500 hover:text-ink-300"
            }`}
            onClick={() => setScope("address")}
            title="References to this exact address"
          >
            addr
          </button>
        </div>
        <button
          className="icon-btn size-5"
          title="Refresh references"
          onClick={() => setRefreshKey((value) => value + 1)}
        >
          <RefreshCw className={`size-3 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      <div className="flex h-7 shrink-0 border-b border-edge">
        <button
          className={`flex flex-1 items-center justify-center gap-1 border-b-2 text-[9.5px] font-medium ${
            direction === "incoming"
              ? "border-accent-400 bg-obsidian-800 text-accent-300"
              : "border-transparent text-ink-500 hover:text-ink-300"
          }`}
          onClick={() => setDirection("incoming")}
        >
          Incoming
          <span className="font-mono text-[8.5px] text-ink-600">
            {incoming.total}
          </span>
        </button>
        <button
          className={`flex flex-1 items-center justify-center gap-1 border-b-2 text-[9.5px] font-medium ${
            direction === "outgoing"
              ? "border-accent-400 bg-obsidian-800 text-accent-300"
              : "border-transparent text-ink-500 hover:text-ink-300"
          }`}
          onClick={() => setDirection("outgoing")}
        >
          Outgoing
          <span className="font-mono text-[8.5px] text-ink-600">
            {outgoing.total}
          </span>
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {loading && page.references.length === 0 && (
          <div className="flex h-24 items-center justify-center gap-2 text-[10.5px] text-ink-500">
            <Loader2 className="size-3.5 animate-spin text-accent-400" />
            Resolving references…
          </div>
        )}

        {error && (
          <div className="m-2 rounded border border-red-500/25 bg-red-500/5 p-2 text-[10px] text-red-300/90">
            {error}
          </div>
        )}

        {!error && !loading && page.references.length === 0 && (
          <div className="p-4 text-center text-[10.5px] text-ink-500">
            {direction === "incoming"
              ? "No incoming references to this target."
              : "No outgoing references from this target."}
          </div>
        )}

        {page.references.map((reference, index) => {
          const counterpart =
            direction === "incoming" ? reference.from : reference.to;
          const counterpartFunction =
            direction === "incoming"
              ? reference.sourceFunction
              : reference.targetFunction;
          return (
            <button
              key={`${reference.from}-${reference.to}-${index}`}
              className="flex w-full items-start gap-1.5 border-b border-edge/60 px-2 py-1.5 text-left hover:bg-obsidian-800"
              onClick={() => openReference(reference)}
              title={`${reference.from} → ${reference.to} (${reference.kind}${reference.dataKind ? `, ${reference.dataKind}` : ""})`}
            >
              <span
                className={`mt-0.5 shrink-0 rounded px-1 font-mono text-[8.5px] uppercase ${kindClass(reference.kind)}`}
              >
                {kindLabels[reference.kind] ?? reference.kind}
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-1 font-mono text-[10.5px] text-ink-300">
                  <span className="truncate">{formatHex(counterpart)}</span>
                  <MoveRight className="size-2.5 shrink-0 text-ink-600" />
                  <span className="truncate text-[9px] text-ink-500">
                    {counterpartFunction?.name ??
                      (reference.kind === "data"
                        ? reference.targetSection ??
                          dataKindLabel(reference.dataKind) ??
                          "data"
                        : "unmapped")}
                  </span>
                </span>
                <span className="mt-0.5 flex items-center gap-1 font-mono text-[9px] text-ink-600">
                  <span>{reference.from}</span>
                  <span>→</span>
                  <span>{reference.to}</span>
                  {reference.kind === "data" && reference.dataKind && (
                    <span className="ml-1 text-ink-600">
                      {dataKindLabel(reference.dataKind)}
                    </span>
                  )}
                </span>
              </span>
            </button>
          );
        })}

        {page.references.length < page.total && (
          <div className="px-2 py-2 text-center font-mono text-[9px] text-ink-600">
            Showing {page.references.length} of {page.total} references
          </div>
        )}
      </div>
    </div>
  );
}
