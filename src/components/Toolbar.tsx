import {
  ArrowLeft,
  ArrowRight,
  Binary,
  CircleStop,
  Crosshair,
  Database,
  FilePlus2,
  FolderOpen,
  FolderSearch,
  Loader2,
  RotateCcw,
  ScanSearch,
  Search,
  Settings,
  X,
} from "lucide-react";
import { useSession } from "../state/session";
import { useWorkspace } from "../state/workspace";

interface ToolbarProps {
  onOpenPalette: () => void;
  onOpenGoTo: () => void;
  onOpenSettings: () => void;
}

export function Toolbar({
  onOpenPalette,
  onOpenGoTo,
  onOpenSettings,
}: ToolbarProps) {
  const {
    binary,
    project,
    projectPath,
    busy,
    openBinaryDialog,
    closeBinary,
    newProject,
    openProjectDialog,
    analysis,
    analysisRunning,
    analysisProgress,
    startAnalysis,
    cancelAnalysis,
    canGoBack,
    canGoForward,
    goBack,
    goForward,
  } = useSession();
  const { resetLayout } = useWorkspace();

  return (
    <header className="flex h-11 shrink-0 items-center gap-1.5 border-b border-edge bg-obsidian-900 px-2.5">
      <div className="flex select-none items-center gap-2 pr-1">
        <div className="flex size-7 items-center justify-center rounded-md border border-accent-500/40 bg-gradient-to-br from-accent-500/30 to-accent-600/10">
          <Binary className="size-4 text-accent-300" strokeWidth={2.2} />
        </div>
        <div className="text-[14px] font-bold tracking-[0.22em] text-ink-100">
          URA
        </div>
      </div>

      <div className="mx-1 h-5 w-px bg-edge" />

      <button
        className="btn"
        onClick={openBinaryDialog}
        title="Open binary (Ctrl+O)"
      >
        <FolderOpen className="size-3.5 text-accent-300" />
        Open
      </button>

      {binary && (
        <button
          className="icon-btn"
          onClick={closeBinary}
          title="Close binary"
          aria-label="Close binary"
        >
          <X className="size-3.5" />
        </button>
      )}

      <div className="mx-1 h-5 w-px bg-edge" />

      <button
        className="btn"
        onClick={newProject}
        disabled={!binary}
        title="Create an analysis project (Ctrl+N)"
      >
        <FilePlus2 className="size-3.5" />
        New Project
      </button>
      <button
        className="btn"
        onClick={openProjectDialog}
        title="Open an analysis project (Ctrl+Shift+O)"
      >
        <FolderSearch className="size-3.5" />
        Open Project
      </button>

      {binary && (
        <>
          <button
            className="btn"
            onClick={startAnalysis}
            disabled={analysisRunning}
            title={
              analysis
                ? `Re-analyze binary (${analysis.functionCount} functions, ${analysis.blockCount} blocks)`
                : "Analyze current binary"
            }
          >
            {analysisRunning ? (
              <Loader2 className="size-3.5 animate-spin text-accent-400" />
            ) : (
              <ScanSearch className="size-3.5 text-accent-300" />
            )}
            {analysisRunning ? "Analyzing…" : "Analyze"}
          </button>
          {analysisRunning && (
            <button
              className="icon-btn"
              onClick={cancelAnalysis}
              title="Cancel analysis"
              aria-label="Cancel analysis"
            >
              <CircleStop className="size-3.5 text-red-400" />
            </button>
          )}
          {analysisRunning && analysisProgress && (
            <span className="hidden max-w-56 truncate font-mono text-[10px] text-ink-500 xl:inline">
              {analysisProgress.stage} · {analysisProgress.functions} fn ·{" "}
              {analysisProgress.instructions} insn
            </span>
          )}
        </>
      )}

      {project && (
        <div
          className="ml-1 flex min-w-0 items-center gap-1.5 rounded-md border border-edge-strong bg-obsidian-850 px-2 py-1 text-[11.5px] text-ink-300"
          title={projectPath ?? project.project.name}
        >
          <Database className="size-3.5 shrink-0 text-emerald-400" />
          <span className="max-w-44 truncate font-medium text-ink-200">
            {project.project.name}
          </span>
          {project.binaryStatus !== "unchanged" && (
            <span
              className={`font-mono text-[9px] uppercase tracking-wider ${
                project.binaryStatus === "modified"
                  ? "text-amber-400"
                  : "text-red-400"
              }`}
            >
              {project.binaryStatus}
            </span>
          )}
        </div>
      )}

      <div className="flex-1" />

      {busy && (
        <div className="flex max-w-60 items-center gap-1.5 truncate text-[11px] text-ink-400">
          <Loader2 className="size-3.5 shrink-0 animate-spin text-accent-400" />
          <span className="truncate">{busy}</span>
        </div>
      )}

      <div className="flex overflow-hidden rounded-md border border-edge-strong">
        <button
          className="icon-btn h-7 w-7 rounded-none border-0 disabled:opacity-35"
          onClick={goBack}
          disabled={!canGoBack}
          title="Back (Alt+Left)"
          aria-label="Back"
        >
          <ArrowLeft className="size-3.5" />
        </button>
        <button
          className="icon-btn h-7 w-7 rounded-none border-0 border-l border-edge-strong disabled:opacity-35"
          onClick={goForward}
          disabled={!canGoForward}
          title="Forward (Alt+Right)"
          aria-label="Forward"
        >
          <ArrowRight className="size-3.5" />
        </button>
      </div>

      <button
        className="btn"
        onClick={onOpenGoTo}
        title="Go to address or symbol (Ctrl+G)"
      >
        <Crosshair className="size-3.5" />
        Go to
        <span className="kbd ml-0.5">Ctrl G</span>
      </button>

      <button
        className="icon-btn"
        onClick={onOpenPalette}
        title="Command palette (Ctrl+K)"
        aria-label="Open command palette"
      >
        <Search className="size-3.5" />
      </button>

      <div className="mx-1 h-5 w-px bg-edge" />

      <button
        className="icon-btn"
        onClick={onOpenSettings}
        title="Settings (Ctrl+,)"
        aria-label="Open settings"
      >
        <Settings className="size-3.5" />
      </button>
      <button
        className="icon-btn"
        onClick={resetLayout}
        title="Reset workspace layout"
        aria-label="Reset workspace layout"
      >
        <RotateCcw className="size-3.5" />
      </button>
    </header>
  );
}
