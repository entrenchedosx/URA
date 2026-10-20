import {
  ArrowRight,
  Binary,
  Braces,
  Cpu,
  Database,
  FileSearch,
  FolderOpen,
  FolderSearch,
  Keyboard,
  ScanSearch,
  ShieldCheck,
} from "lucide-react";

interface WelcomeProps {
  onOpenBinary: () => void;
  onOpenProject: () => void;
  hasProjectSupport: boolean;
}

const shortcuts: Array<[string, string]> = [
  ["Ctrl+O", "Open binary"],
  ["Ctrl+K", "Go to address / symbol"],
  ["Ctrl+1 … 4", "Switch workspace view"],
  ["Ctrl+N", "New analysis project"],
  ["Ctrl+Shift+O", "Open analysis project"],
  ["Ctrl+Enter", "Save annotation"],
];

const capabilities = [
  {
    icon: FileSearch,
    title: "Native parsing",
    text: "PE, ELF and Mach-O metadata read directly from disk — no guessing, no simulation.",
  },
  {
    icon: Cpu,
    title: "Real x86 / x64",
    text: "Instruction decoding through iced-x86 with flow classification and branch targets.",
  },
  {
    icon: ScanSearch,
    title: "Strings & hex",
    text: "Scan ASCII and UTF-16LE strings, then jump file offsets straight into the hex view.",
  },
  {
    icon: Database,
    title: "Persistent analysis",
    text: "Annotate addresses and store them in a SQLite project with binary integrity checks.",
  },
];

export function Welcome({
  onOpenBinary,
  onOpenProject,
  hasProjectSupport,
}: WelcomeProps) {
  return (
    <div className="relative flex h-full w-full items-center justify-center overflow-auto bg-obsidian-950">
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(59,130,246,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.06) 1px, transparent 1px)",
          backgroundSize: "44px 44px",
          maskImage:
            "radial-gradient(ellipse 70% 60% at 50% 42%, black 20%, transparent 75%)",
        }}
      />
      <div className="relative z-10 w-full max-w-3xl px-8 py-10">
        <div className="mb-8 flex items-center gap-4">
          <div className="flex size-14 items-center justify-center rounded-xl border border-accent-500/40 bg-gradient-to-br from-accent-500/25 to-obsidian-800 shadow-[0_0_40px_rgba(59,130,246,0.2)]">
            <Binary className="size-7 text-accent-300" strokeWidth={1.9} />
          </div>
          <div>
            <div className="text-[32px] font-bold leading-none tracking-[0.3em] text-ink-100">
              URA
            </div>
            <div className="mt-1.5 text-[10px] font-semibold uppercase tracking-[0.3em] text-accent-400/80">
              Ultimate Reverse Engineer
            </div>
          </div>
          <span className="ml-2 rounded-full border border-edge-strong bg-obsidian-850 px-2 py-0.5 font-mono text-[10px] text-ink-400">
            v0.1.0
          </span>
        </div>

        <p className="mb-6 max-w-xl text-[14px] leading-relaxed text-ink-300">
          A native inspection workbench for compiled binaries. Load an image to
          examine its headers, sections, symbols and imports, disassemble code,
          inspect raw bytes, harvest strings, and keep your analysis anchored in
          a durable project.
        </p>

        <div className="mb-8 flex flex-wrap items-center gap-2.5">
          <button className="btn-primary h-9 px-4 text-[13px]" onClick={onOpenBinary}>
            <FolderOpen className="size-4" />
            Open Binary
            <span className="kbd ml-1 border-white/20 bg-white/10 text-white/70">
              Ctrl O
            </span>
          </button>
          <button
            className="btn h-9 px-3.5 text-[12.5px]"
            onClick={onOpenProject}
            disabled={!hasProjectSupport}
            title="Open a .ura analysis project"
          >
            <FolderSearch className="size-4" />
            Open Analysis Project
          </button>
          <div className="ml-1 flex items-center gap-1.5 text-[11px] text-ink-500">
            <ShieldCheck className="size-3.5 text-emerald-400/80" />
            Binaries are opened read-only and never executed
          </div>
        </div>

        <div className="mb-8 grid grid-cols-2 gap-2.5">
          {capabilities.map((item) => (
            <div
              key={item.title}
              className="group flex gap-3 rounded-lg border border-edge bg-obsidian-850/70 p-3 transition-colors hover:border-edge-strong hover:bg-obsidian-800/80"
            >
              <item.icon className="mt-0.5 size-4 shrink-0 text-accent-400/90" />
              <div>
                <div className="text-[12px] font-semibold text-ink-200">
                  {item.title}
                </div>
                <div className="mt-0.5 text-[11px] leading-relaxed text-ink-400">
                  {item.text}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-[1fr_auto] gap-6">
          <div className="rounded-lg border border-edge bg-obsidian-850/50 p-3.5">
            <div className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-500">
              <Keyboard className="size-3" />
              Keyboard
            </div>
            <div className="grid grid-cols-2 gap-x-6 gap-y-1.5">
              {shortcuts.map(([keys, action]) => (
                <div
                  key={keys}
                  className="flex items-center justify-between gap-3 text-[11px]"
                >
                  <span className="text-ink-400">{action}</span>
                  <span className="kbd shrink-0">{keys}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="flex flex-col justify-between rounded-lg border border-edge bg-obsidian-850/50 p-3.5 text-[11px] text-ink-400">
            <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-500">
              <Braces className="size-3" />
              Formats
            </div>
            <div className="mt-2 space-y-1">
              <div className="flex items-center justify-between gap-5">
                <span>PE / PE32+</span>
                <span className="text-emerald-400">supported</span>
              </div>
              <div className="flex items-center justify-between gap-5">
                <span>ELF 32 / 64</span>
                <span className="text-emerald-400">supported</span>
              </div>
              <div className="flex items-center justify-between gap-5">
                <span>Mach-O</span>
                <span className="text-emerald-400">metadata</span>
              </div>
              <div className="flex items-center justify-between gap-5">
                <span>Disassembly</span>
                <span className="text-accent-300">x86 / x64</span>
              </div>
            </div>
            <button
              className="mt-3 flex items-center gap-1 text-[11px] text-accent-400 transition-colors hover:text-accent-300"
              onClick={onOpenBinary}
            >
              Select a binary <ArrowRight className="size-3" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
