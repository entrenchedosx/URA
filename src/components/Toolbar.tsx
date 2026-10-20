import {
  Binary,
  Crosshair,
  Database,
  FilePlus2,
  FolderOpen,
  FolderSearch,
  Loader2,
  RotateCcw,
  Settings,
  X,
} from "lucide-react";
import { useSession } from "../state/session";
import { useWorkspace } from "../state/workspace";

interface ToolbarProps {
  onOpenPalette: () => void;
  onOpenSettings: () => void;
}

export function Toolbar({ onOpenPalette, onOpenSettings }: ToolbarProps) {
  const {
    binary,
    project,
    projectPath,
    busy,
    openBinaryDialog,
    closeBinary,
    newProject,
    openProjectDialog,
  } = useSession();
  const { resetLayout } = useWorkspace();

  return (
    <header className="flex h-11 shrink-0 items-center gap-1.5 border-b border-edge bg-obsidian-900 px-2.5">
      <div className="flex select-none items-center gap-2 pr-1">
        <div className="flex size-7 items-center justify-center rounded-md border border-accent-500/40 bg-gradient-to-br from-accent-500/30 to-accent-600/10 shadow-[0_0_18px_rgba(77,143,232,0.18)]">
          <Binary className="size-4 text-accent-300" strokeWidth={2.2} />
        </div>
        <div className="leading-none">
          <div className="text-[14px] font-bold tracking-[0.22em] text-ink-100">
            URA
          </div>
          <div className="mt-0.5 text-[8px] font-semibold tracking-[0.16em] text-ink-500">
            ULTIMATE REVERSE ENGINEER
          </div>
        </div>
      </div>

      <div className="mx-1 h-5 w-px bg-edge" />

      <button
        className="btn"
        onClick={openBinaryDialog}
        title="Open binary (Ctrl+O)"
      >
        <FolderOpen className="size-3.5 text-accent-300" />
        Open Binary
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

      <button
        className="btn"
        onClick={onOpenPalette}
        title="Go to address or symbol (Ctrl+K)"
      >
        <Crosshair className="size-3.5" />
        Go to
        <span className="kbd ml-0.5">Ctrl K</span>
      </button>

      <div className="mx-1 h-5 w-px bg-edge" />

      <button
        className="icon-btn"
        onClick={onOpenSettings}
        title="Preferences (Ctrl+,)"
        aria-label="Open preferences"
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
