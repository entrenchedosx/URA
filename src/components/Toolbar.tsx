import {
  Binary,
  Crosshair,
  Database,
  FilePlus2,
  FolderOpen,
  FolderSearch,
  Loader2,
  X,
} from "lucide-react";
import type { BinaryOpenResult, ProjectInfo } from "../lib/types";

interface ToolbarProps {
  binary: BinaryOpenResult | null;
  project: ProjectInfo | null;
  projectPath: string | null;
  busy: string | null;
  onOpenBinary: () => void;
  onCloseBinary: () => void;
  onNewProject: () => void;
  onOpenProject: () => void;
  onGoTo: () => void;
}

export function Toolbar({
  binary,
  project,
  projectPath,
  busy,
  onOpenBinary,
  onCloseBinary,
  onNewProject,
  onOpenProject,
  onGoTo,
}: ToolbarProps) {
  return (
    <header className="flex h-12 shrink-0 items-center gap-2 border-b border-edge bg-obsidian-900 px-3">
      <div className="flex select-none items-center gap-2.5 pr-2">
        <div className="flex size-7 items-center justify-center rounded-md border border-accent-500/40 bg-gradient-to-br from-accent-500/30 to-accent-600/10 shadow-[0_0_18px_rgba(59,130,246,0.18)]">
          <Binary className="size-4 text-accent-300" strokeWidth={2.2} />
        </div>
        <div className="leading-none">
          <div className="text-[15px] font-bold tracking-[0.22em] text-ink-100">
            URA
          </div>
          <div className="mt-0.5 text-[8.5px] font-semibold tracking-[0.16em] text-ink-500">
            ULTIMATE REVERSE ENGINEER
          </div>
        </div>
      </div>

      <div className="mx-1 h-5 w-px bg-edge" />

      <button className="btn" onClick={onOpenBinary} title="Open binary (Ctrl+O)">
        <FolderOpen className="size-3.5 text-accent-300" />
        Open Binary
      </button>

      {binary && (
        <button
          className="icon-btn"
          onClick={onCloseBinary}
          title="Close binary"
          aria-label="Close binary"
        >
          <X className="size-3.5" />
        </button>
      )}

      <div className="mx-1 h-5 w-px bg-edge" />

      <button
        className="btn"
        onClick={onNewProject}
        disabled={!binary}
        title="Create an analysis project (Ctrl+N)"
      >
        <FilePlus2 className="size-3.5" />
        New Project
      </button>
      <button
        className="btn"
        onClick={onOpenProject}
        title="Open an analysis project (Ctrl+Shift+O)"
      >
        <FolderSearch className="size-3.5" />
        Open Project
      </button>

      {project && (
        <div
          className="ml-1 flex min-w-0 items-center gap-1.5 rounded-md border border-edge-strong bg-obsidian-850 px-2 py-1 text-[11.5px] text-ink-300"
          title={projectPath ?? project.name}
        >
          <Database className="size-3.5 shrink-0 text-emerald-400" />
          <span className="max-w-44 truncate font-medium text-ink-200">
            {project.name}
          </span>
        </div>
      )}

      <div className="flex-1" />

      {busy && (
        <div className="flex items-center gap-1.5 text-[11.5px] text-ink-400">
          <Loader2 className="size-3.5 animate-spin text-accent-400" />
          {busy}
        </div>
      )}

      <button className="btn" onClick={onGoTo} title="Go to address or symbol (Ctrl+K)">
        <Crosshair className="size-3.5" />
        Go to
        <span className="kbd ml-0.5">Ctrl K</span>
      </button>

      <button className="btn-primary" onClick={onOpenBinary}>
        <FolderOpen className="size-3.5" />
        Analyze File
      </button>
    </header>
  );
}
