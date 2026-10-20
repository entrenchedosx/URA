import { Binary, FolderOpen, FolderSearch, Keyboard } from "lucide-react";
import { useSession } from "../state/session";

const shortcuts: Array<[string, string]> = [
  ["Ctrl+O", "Open file"],
  ["Ctrl+G", "Go to address"],
  ["Ctrl+K", "Command palette"],
  ["Ctrl+Shift+O", "Open project"],
  ["Ctrl+N", "New project"],
  ["Alt+Left / Alt+Right", "History"],
  ["F2", "Rename function"],
  ["Ctrl+,", "Settings"],
];

export function Welcome() {
  const { openBinaryDialog, openProjectDialog } = useSession();

  return (
    <div className="absolute inset-0 z-20 flex items-center justify-center overflow-auto bg-obsidian-950 px-8">
      <div className="w-full max-w-xl">
        <div className="flex items-center gap-3">
          <div className="flex size-11 items-center justify-center rounded-lg border border-accent-500/40 bg-gradient-to-br from-accent-500/25 to-obsidian-800">
            <Binary className="size-5 text-accent-300" strokeWidth={1.9} />
          </div>
          <div className="text-[28px] font-bold leading-none tracking-[0.3em] text-ink-100">
            URA
          </div>
          <span className="rounded-full border border-edge-strong bg-obsidian-850 px-2 py-0.5 font-mono text-[10px] text-ink-400">
            v0.4.0
          </span>
        </div>

        <div className="mt-2 text-[11.5px] text-ink-500">
          Static binary analysis
        </div>

        <div className="mt-7 flex flex-wrap gap-2">
          <button className="btn-primary h-8 px-3.5" onClick={openBinaryDialog}>
            <FolderOpen className="size-4" />
            Open File
            <span className="kbd ml-1 border-white/20 bg-white/10 text-white/70">
              Ctrl O
            </span>
          </button>
          <button className="btn h-8 px-3" onClick={openProjectDialog}>
            <FolderSearch className="size-4" />
            Open Project
          </button>
        </div>

        <div className="mt-10 border-t border-edge pt-4">
          <div className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-ink-500">
            <Keyboard className="size-3" />
            Keyboard
          </div>
          <div className="grid grid-cols-1 gap-x-8 gap-y-1.5 sm:grid-cols-2">
            {shortcuts.map(([keys, action]) => (
              <div
                key={keys}
                className="flex items-center justify-between gap-3 whitespace-nowrap text-[11px]"
              >
                <span className="text-ink-400">{action}</span>
                <span className="kbd shrink-0">{keys}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
