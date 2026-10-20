import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  CircleStop,
  Clipboard,
  GitFork,
  Loader2,
  Pencil,
  Play,
  Plus,
  ScanSearch,
  Share2,
  Trash2,
} from "lucide-react";
import {
  errorMessage,
  listFunctions,
} from "../lib/api";
import {
  addressToOffset,
  formatHex,
} from "../lib/format";
import type {
  FunctionSort,
  FunctionSummary,
} from "../lib/types";
import { useMessages } from "../state/messages";
import { useSession } from "../state/session";
import { ContextMenu, type ContextMenuItem } from "./ContextMenu";
import { VirtualList } from "./VirtualList";

const PAGE_SIZE = 500;

const sortOptions: Array<{ id: FunctionSort; label: string }> = [
  { id: "address", label: "Address" },
  { id: "name", label: "Name" },
  { id: "instructions", label: "Instructions" },
  { id: "blocks", label: "Blocks" },
  { id: "references", label: "References" },
];

const originLabels: Record<string, string> = {
  entryPoint: "entry",
  export: "export",
  symbol: "symbol",
  callTarget: "call",
  user: "user",
};

const originColors: Record<string, string> = {
  entryPoint: "bg-accent-400",
  export: "bg-emerald-400",
  symbol: "bg-sky-400",
  callTarget: "bg-ink-600",
  user: "bg-fuchsia-400",
};

function formatCount(value: number): string {
  return value.toLocaleString();
}

export function FunctionExplorer({ search }: { search: string }) {
  const {
    binary,
    analysis,
    analysisRunning,
    analysisProgress,
    analysisError,
    functionRevision,
    currentFunction,
    setSelection,
    navigate,
    startAnalysis,
    cancelAnalysis,
    openCfg,
    openXrefs,
    requestRename,
    projectPath,
    createUserFunction,
    deleteUserFunction,
  } = useSession();
  const { log } = useMessages();

  const [sort, setSort] = useState<FunctionSort>("address");
  const [descending, setDescending] = useState(false);
  const [debouncedSearch, setDebouncedSearch] = useState(search.trim());
  const [functions, setFunctions] = useState<FunctionSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [menu, setMenu] = useState<{
    x: number;
    y: number;
    fn: FunctionSummary;
  } | null>(null);

  const requestId = useRef(0);
  const loadingRef = useRef(false);

  useEffect(() => {
    const timeout = window.setTimeout(
      () => setDebouncedSearch(search.trim()),
      180,
    );
    return () => window.clearTimeout(timeout);
  }, [search]);

  const runQuery = useCallback(
    (offset: number, append: boolean) => {
      if (loadingRef.current) return;
      loadingRef.current = true;
      const id = requestId.current;
      setLoading(true);
      listFunctions({
        search: debouncedSearch,
        sort,
        descending,
        offset,
        limit: PAGE_SIZE,
      })
        .then((page) => {
          if (id !== requestId.current) return;
          setTotal(page.total);
          setFunctions((previous) =>
            append ? [...previous, ...page.functions] : page.functions,
          );
          setError(null);
        })
        .catch((err) => {
          if (id !== requestId.current) return;
          setError(errorMessage(err));
        })
        .finally(() => {
          if (id !== requestId.current) return;
          loadingRef.current = false;
          setLoading(false);
        });
    },
    [debouncedSearch, sort, descending],
  );

  useEffect(() => {
    requestId.current += 1;
    loadingRef.current = false;
    setFunctions([]);
    setTotal(0);
    setError(null);
    if (!analysis) {
      setLoading(false);
      return;
    }
    runQuery(0, false);
  }, [analysis, functionRevision, runQuery]);

  const loadMore = useCallback(() => {
    if (loadingRef.current || functions.length >= total) return;
    runQuery(functions.length, true);
  }, [functions.length, total, runQuery]);

  const openFunction = useCallback(
    (fn: FunctionSummary) => {
      navigate({ address: fn.address }, "disassembly");
    },
    [navigate],
  );

  const selectFunction = useCallback(
    (fn: FunctionSummary) => {
      setSelection({
        address: fn.address,
        fileOffset: binary
          ? addressToOffset(binary.sections, fn.address)
          : null,
      });
    },
    [binary, setSelection],
  );

  const copy = useCallback(
    (text: string, label: string) => {
      navigator.clipboard.writeText(text).catch((err) => {
        log("warning", `Unable to copy ${label}: ${errorMessage(err)}`);
      });
    },
    [log],
  );

  const menuItems: ContextMenuItem[] = useMemo(() => {
    if (!menu) return [];
    const fn = menu.fn;
    return [
      {
        label: "Open in disassembly",
        icon: Play,
        onSelect: () => openFunction(fn),
      },
      {
        label: "Show control flow",
        icon: GitFork,
        onSelect: () => openCfg(fn.address),
      },
      {
        label: "Show references",
        icon: Share2,
        onSelect: () => openXrefs(fn.address),
      },
      { label: "-", onSelect: () => undefined },
      {
        label: "Rename function",
        icon: Pencil,
        shortcut: "F2",
        disabled: !projectPath,
        onSelect: () => requestRename(fn.address),
      },
      ...(projectPath && fn.origin !== "user"
        ? [
            {
              label: "Mark as user-defined",
              icon: Plus,
              onSelect: () => createUserFunction(fn.address),
            },
          ]
        : []),
      ...(projectPath && fn.origin === "user"
        ? [
            {
              label: "Delete user-defined function",
              icon: Trash2,
              onSelect: () => deleteUserFunction(fn.address),
            },
          ]
        : []),
      {
        label: "Copy address",
        icon: Clipboard,
        onSelect: () => copy(fn.address, "address"),
      },
    ];
  }, [
    menu,
    openFunction,
    openCfg,
    openXrefs,
    requestRename,
    projectPath,
    createUserFunction,
    deleteUserFunction,
    copy,
  ]);

  const activeAddress = currentFunction?.address ?? null;

  if (!analysis && !analysisRunning) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 bg-obsidian-850 p-5 text-center">
        <ScanSearch className="size-5 text-ink-600" />
        <div className="text-[11px] leading-relaxed text-ink-500">
          {analysisError
            ? `Function analysis failed: ${analysisError}`
            : "Function analysis has not been run for this binary."}
        </div>
        <button
          className="btn h-7 px-2.5 text-[11px]"
          onClick={startAnalysis}
          disabled={!binary}
        >
          <Play className="size-3.5" />
          Analyze functions
        </button>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-obsidian-850">
      <div className="flex h-7 shrink-0 items-center gap-1.5 border-b border-edge px-2">
        <select
          className="h-5.5 max-w-[120px] rounded border border-edge-strong bg-obsidian-900 px-1 font-mono text-[9.5px] text-ink-300 focus:border-accent-500/70 focus:outline-none"
          value={sort}
          onChange={(event) => setSort(event.target.value as FunctionSort)}
          aria-label="Sort functions"
        >
          {sortOptions.map((option) => (
            <option key={option.id} value={option.id}>
              {option.label}
            </option>
          ))}
        </select>
        <button
          className="icon-btn size-5"
          title={descending ? "Descending" : "Ascending"}
          onClick={() => setDescending((value) => !value)}
        >
          {descending ? (
            <ArrowDown className="size-3" />
          ) : (
            <ArrowUp className="size-3" />
          )}
        </button>
        <span className="flex-1" />
        <span className="font-mono text-[9.5px] text-ink-500">
          {loading ? "…" : `${formatCount(total)} functions`}
        </span>
      </div>

      {analysisRunning && (
        <div className="shrink-0 border-b border-edge bg-obsidian-900/70 px-2 py-1">
          <div className="flex items-center gap-1.5 text-[9.5px] text-ink-400">
            <Loader2 className="size-2.5 animate-spin text-accent-400" />
            <span className="flex-1 truncate">
              {analysisProgress
                ? `${analysisProgress.stage} · ${formatCount(analysisProgress.instructions)} instructions · ${formatCount(analysisProgress.functions)} functions`
                : "Analyzing functions…"}
            </span>
            <button
              className="icon-btn size-4"
              title="Cancel analysis"
              onClick={cancelAnalysis}
            >
              <CircleStop className="size-3 text-red-400" />
            </button>
          </div>
          <div className="mt-1 h-0.5 overflow-hidden rounded bg-obsidian-700">
            <div className="h-full w-1/3 animate-pulse rounded bg-accent-500" />
          </div>
        </div>
      )}

      {analysis && (analysis.cancelled || analysis.truncated) && (
        <div className="shrink-0 border-b border-amber-500/20 bg-amber-500/5 px-2 py-1 text-[9.5px] text-amber-300/90">
          {analysis.cancelled
            ? "Partial analysis — results are incomplete."
            : "Analysis stopped at a safety limit — results are partial."}
        </div>
      )}

      {analysis && analysis.diagnostics.length > 0 && (
        <div
          className="shrink-0 border-b border-amber-500/15 px-2 py-1 font-mono text-[9px] text-amber-400/80"
          title={analysis.diagnostics
            .slice(0, 6)
            .map(
              (diagnostic) =>
                `${diagnostic.address ?? "—"}: ${diagnostic.message}`,
            )
            .join("\n")}
        >
          {analysis.diagnostics.length} diagnostics
          {analysis.diagnosticsDropped > 0
            ? ` (+${analysis.diagnosticsDropped} dropped)`
            : ""}
        </div>
      )}

      {error && (
        <div className="m-2 rounded border border-red-500/25 bg-red-500/5 p-2 text-[10px] text-red-300/90">
          {error}
        </div>
      )}

      {!error && (
        <div className="min-h-0 flex-1">
          <VirtualList
            className="h-full"
            count={functions.length}
            estimateSize={46}
            overscan={14}
            onEndReached={loadMore}
            renderRow={(index) => {
              const fn = functions[index];
              const active = fn.address === activeAddress;
              return (
                <button
                  className={`flex h-[46px] w-full flex-col justify-center gap-0.5 border-l-2 px-2.5 text-left transition-colors ${
                    active
                      ? "border-accent-400 bg-accent-500/10"
                      : "border-transparent hover:bg-obsidian-750/70"
                  }`}
                  onClick={() => selectFunction(fn)}
                  onDoubleClick={() => openFunction(fn)}
                  onContextMenu={(event) => {
                    event.preventDefault();
                    selectFunction(fn);
                    setMenu({ x: event.clientX, y: event.clientY, fn });
                  }}
                  title={`${fn.name} — ${fn.address} · ${formatCount(fn.instructionCount)} instructions`}
                >
                  <span className="flex min-w-0 items-center gap-1.5">
                    <span
                      className={`size-1 shrink-0 rounded-full ${
                        originColors[fn.origin] ?? "bg-obsidian-600"
                      }`}
                    />
                    <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink-200">
                      {fn.name}
                    </span>
                    {fn.customName && (
                      <Pencil className="size-2.5 shrink-0 text-accent-400/80" />
                    )}
                    <span className="shrink-0 rounded bg-obsidian-700/70 px-1 font-mono text-[8.5px] uppercase tracking-wide text-ink-500">
                      {originLabels[fn.origin] ?? fn.origin}
                    </span>
                  </span>
                  <span className="flex min-w-0 items-center gap-1.5 overflow-hidden whitespace-nowrap pl-2.5 font-mono text-[9px] text-ink-500">
                    <span className="text-ink-400">{formatHex(fn.address)}</span>
                    <span>·</span>
                    <span>{formatCount(fn.instructionCount)} insn</span>
                    <span>·</span>
                    <span>{formatCount(fn.blockCount)} blocks</span>
                    {fn.referenceCount > 0 && (
                      <>
                        <span>·</span>
                        <span>{formatCount(fn.referenceCount)} refs</span>
                      </>
                    )}
                  </span>
                </button>
              );
            }}
          />
          {loading && functions.length === 0 && (
            <div className="flex h-24 items-center justify-center gap-2 text-[10.5px] text-ink-500">
              <Loader2 className="size-3.5 animate-spin text-accent-400" />
              Loading functions…
            </div>
          )}
          {!loading && functions.length === 0 && !error && (
            <div className="p-4 text-center text-[10.5px] text-ink-500">
              {debouncedSearch
                ? "No functions match the filter."
                : "No functions were discovered."}
            </div>
          )}
        </div>
      )}

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
