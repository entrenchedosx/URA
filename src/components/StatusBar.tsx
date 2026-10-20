import {
  AlertTriangle,
  CircleCheck,
  CircleDot,
  Database,
  GitFork,
  Loader2,
  MessageSquare,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { formatHex, formatSize } from "../lib/format";
import { WORKSPACE_PANEL_TITLES } from "../lib/panels";
import { useMessages } from "../state/messages";
import { useSession } from "../state/session";
import { useWorkspace } from "../state/workspace";

function StatusBadge({ status }: { status: string | null }) {
  if (!status) {
    return (
      <span className="flex items-center gap-1 text-ink-500">
        <CircleDot className="size-3" />
        no project
      </span>
    );
  }
  if (status === "unchanged") {
    return (
      <span className="flex items-center gap-1 text-emerald-400">
        <ShieldCheck className="size-3" />
        binary verified
      </span>
    );
  }
  if (status === "modified") {
    return (
      <span className="flex items-center gap-1 text-amber-400">
        <ShieldAlert className="size-3" />
        binary modified
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1 text-red-400">
      <AlertTriangle className="size-3" />
      binary missing
    </span>
  );
}

export function StatusBar() {
  const {
    binary,
    project,
    projectPath,
    selection,
    busy,
    scanning,
    analysis,
    analysisRunning,
    analysisProgress,
  } = useSession();
  const { messages } = useMessages();
  const { activePanelId, openPanels, togglePanel } = useWorkspace();

  const binaryStatus = project?.binaryStatus ?? null;
  const viewLabel = activePanelId
    ? WORKSPACE_PANEL_TITLES[activePanelId]
    : "No panel";
  const messagesOpen = openPanels.includes("messages");

  return (
    <footer className="flex h-7 shrink-0 items-center gap-3 border-t border-edge bg-obsidian-900 px-3 font-mono text-[10.5px] text-ink-400 select-none">
      {binary ? (
        <>
          <span className="flex min-w-0 items-center gap-1.5 text-ink-300">
            <CircleCheck className="size-3 shrink-0 text-emerald-400" />
            <span className="max-w-64 truncate">{binary.info.fileName}</span>
          </span>
          <span className="text-ink-600">|</span>
          <span className="uppercase">{binary.info.format}</span>
          <span>{binary.info.architecture}</span>
          <span>{binary.info.bitness}-bit</span>
          <span className="text-ink-600">|</span>
          <span>{formatSize(binary.info.fileSize)}</span>
          <span>{binary.sections.length} sections</span>
          <span>{binary.symbols.length} symbols</span>
          {(analysis || analysisRunning) && (
            <>
              <span className="text-ink-600">|</span>
              <span className="flex items-center gap-1">
                {analysisRunning ? (
                  <>
                    <Loader2 className="size-3 animate-spin text-accent-400" />
                    <span>
                      analysis {analysisProgress?.functions ?? 0} fn
                    </span>
                  </>
                ) : (
                  <>
                    <GitFork className="size-3 text-accent-400" />
                    <span>
                      {analysis?.functionCount ?? 0} fn ·{" "}
                      {analysis?.blockCount ?? 0} blocks
                      {analysis?.cancelled ? " · partial" : ""}
                    </span>
                  </>
                )}
              </span>
            </>
          )}
        </>
      ) : (
        <span className="text-ink-500">No binary loaded</span>
      )}

      <div className="flex-1" />

      {project && (
        <span className="flex items-center gap-1.5">
          <Database className="size-3 text-ink-500" />
          <span
            className="max-w-40 truncate"
            title={projectPath ?? project.project.name}
          >
            {project.project.name}
          </span>
          <StatusBadge status={binaryStatus} />
        </span>
      )}

      <span className="text-ink-600">|</span>
      <span className="text-ink-500">{viewLabel}</span>

      {selection?.address && (
        <>
          <span className="text-ink-600">|</span>
          <span className="text-accent-300">{formatHex(selection.address)}</span>
        </>
      )}
      {selection?.fileOffset && (
        <span className="text-ink-500">@{formatHex(selection.fileOffset)}</span>
      )}

      <span className="text-ink-600">|</span>
      <button
        className={`flex items-center gap-1 rounded px-1 py-0.5 transition-colors hover:bg-obsidian-750 hover:text-ink-200 ${
          messagesOpen ? "text-accent-300" : ""
        }`}
        onClick={() => togglePanel("messages")}
        title="Toggle message log"
      >
        <MessageSquare className="size-3" />
        {messages.length}
      </button>
      <span className="text-ink-600">|</span>
      <span className="flex min-w-16 items-center gap-1 text-ink-500">
        {busy || scanning ? (
          <>
            <Loader2 className="size-3 animate-spin text-accent-400" />
            <span className="truncate">{busy ?? "Scanning…"}</span>
          </>
        ) : (
          "Ready"
        )}
      </span>
    </footer>
  );
}
