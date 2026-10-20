import { useEffect } from "react";
import { Binary, X } from "lucide-react";

interface AboutDialogProps {
  open: boolean;
  onClose: () => void;
}

export function AboutDialog({ open, onClose }: AboutDialogProps) {
  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 px-4 backdrop-blur-[2px]"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-sm overflow-hidden rounded-xl border border-edge-strong bg-obsidian-850 shadow-[0_24px_80px_rgba(0,0,0,0.65)]">
        <div className="flex items-center gap-2 border-b border-edge bg-obsidian-800 px-3.5 py-2.5">
          <span className="flex-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-ink-400">
            About
          </span>
          <button
            className="icon-btn size-6"
            onClick={onClose}
            aria-label="Close about dialog"
          >
            <X className="size-3.5" />
          </button>
        </div>
        <div className="p-4">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-lg border border-accent-500/40 bg-gradient-to-br from-accent-500/25 to-obsidian-800">
              <Binary className="size-5 text-accent-300" strokeWidth={1.9} />
            </div>
            <div>
              <div className="text-[16px] font-semibold tracking-[0.24em] text-ink-100">
                URA
              </div>
              <div className="text-[10.5px] text-ink-400">
                Ultimate Reverse Engineer
              </div>
            </div>
            <div className="ml-auto font-mono text-[10px] text-ink-500">
              v0.4.0
            </div>
          </div>
          <p className="mt-4 text-[11.5px] leading-relaxed text-ink-400">
            Static binary analysis for PE, ELF and Mach-O images, with x86/x64
            disassembly, function analysis, control-flow graphs and SQLite
            projects. Binaries are opened read-only and never executed.
          </p>
          <div className="mt-4 border-t border-edge pt-3 font-mono text-[9.5px] text-ink-600">
            Tauri · Rust · iced-x86 · React
          </div>
        </div>
      </div>
    </div>
  );
}
