import { useEffect } from "react";
import {
  Columns3,
  Eye,
  EyeOff,
  RotateCcw,
  Rows3,
  Settings,
  Type,
  X,
} from "lucide-react";
import {
  CODE_FONT_MAX,
  CODE_FONT_MIN,
  type Density,
  rowHeightFor,
  useSettings,
} from "../state/settings";
import { useWorkspace } from "../state/workspace";

interface SettingsDialogProps {
  open: boolean;
  onClose: () => void;
}

const densities: Array<{ id: Density; label: string }> = [
  { id: "compact", label: "Compact" },
  { id: "comfortable", label: "Comfortable" },
  { id: "spacious", label: "Spacious" },
];

export function SettingsDialog({ open, onClose }: SettingsDialogProps) {
  const { settings, update, reset } = useSettings();
  const { resetLayout } = useWorkspace();

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
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/55 px-4 pt-[14vh] backdrop-blur-[2px]"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-[460px] overflow-hidden rounded-xl border border-edge-strong bg-obsidian-850 shadow-[0_24px_80px_rgba(0,0,0,0.65)]">
        <div className="flex items-center gap-2 border-b border-edge bg-obsidian-800 px-3.5 py-2.5">
          <Settings className="size-4 text-accent-400" />
          <span className="flex-1 text-[12px] font-semibold uppercase tracking-[0.14em] text-ink-300">
            Preferences
          </span>
          <span className="kbd">Esc</span>
          <button
            className="icon-btn size-6"
            onClick={onClose}
            aria-label="Close preferences"
          >
            <X className="size-3.5" />
          </button>
        </div>

        <div className="space-y-4 p-4">
          <section>
            <div className="mb-2 flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-[11px] font-medium text-ink-300">
                <Type className="size-3.5 text-accent-400" />
                Code font size
              </div>
              <span className="font-mono text-[11px] text-accent-300">
                {settings.codeFontSize} px
              </span>
            </div>
            <input
              type="range"
              min={CODE_FONT_MIN}
              max={CODE_FONT_MAX}
              step={1}
              value={settings.codeFontSize}
              onChange={(event) =>
                update({ codeFontSize: Number(event.target.value) })
              }
              className="w-full accent-[#4d8fe8]"
              aria-label="Code font size"
            />
            <div
              className="mt-2 overflow-hidden rounded-md border border-edge bg-obsidian-900 px-2.5 py-1.5 font-mono text-ink-300"
              style={{ fontSize: settings.codeFontSize }}
            >
              0x140001004&nbsp;&nbsp;mov&nbsp;&nbsp;rax, qword ptr [rip + 0x2f5]
            </div>
          </section>

          <section>
            <div className="mb-2 flex items-center gap-1.5 text-[11px] font-medium text-ink-300">
              <Rows3 className="size-3.5 text-accent-400" />
              Row density
            </div>
            <div className="grid grid-cols-3 gap-1.5">
              {densities.map((density) => (
                <button
                  key={density.id}
                  className={`rounded-md border px-2 py-1.5 text-left transition-colors ${
                    settings.density === density.id
                      ? "border-accent-500/60 bg-accent-500/10 text-ink-100"
                      : "border-edge-strong bg-obsidian-800 text-ink-400 hover:bg-obsidian-750"
                  }`}
                  onClick={() => update({ density: density.id })}
                >
                  <div className="text-[11px] font-medium">{density.label}</div>
                  <div className="font-mono text-[9.5px] text-ink-500">
                    {rowHeightFor({ ...settings, density: density.id })} px rows
                  </div>
                </button>
              ))}
            </div>
          </section>

          <section className="flex items-center justify-between rounded-md border border-edge bg-obsidian-800 px-2.5 py-2">
            <div className="flex items-center gap-2">
              <Columns3 className="size-3.5 text-accent-400" />
              <div>
                <div className="text-[11px] font-medium text-ink-300">
                  Instruction bytes column
                </div>
                <div className="text-[10px] text-ink-500">
                  Show raw encoding alongside disassembly.
                </div>
              </div>
            </div>
            <button
              className={`flex items-center gap-1.5 rounded-md border px-2 py-1 text-[10.5px] transition-colors ${
                settings.showBytes
                  ? "border-accent-500/50 bg-accent-500/10 text-accent-300"
                  : "border-edge-strong bg-obsidian-750 text-ink-400"
              }`}
              onClick={() => update({ showBytes: !settings.showBytes })}
              aria-pressed={settings.showBytes}
            >
              {settings.showBytes ? (
                <Eye className="size-3.5" />
              ) : (
                <EyeOff className="size-3.5" />
              )}
              {settings.showBytes ? "Shown" : "Hidden"}
            </button>
          </section>

          <section className="flex gap-1.5 border-t border-edge pt-3">
            <button
              className="btn flex-1 justify-center"
              onClick={reset}
              title="Restore default preferences"
            >
              <RotateCcw className="size-3.5" />
              Reset preferences
            </button>
            <button
              className="btn flex-1 justify-center"
              onClick={() => {
                resetLayout();
                onClose();
              }}
              title="Rebuild the default dock layout"
            >
              <LayoutIcon />
              Reset layout
            </button>
          </section>
        </div>

        <div className="flex items-center gap-2 border-t border-edge bg-obsidian-900 px-3.5 py-2 font-mono text-[9.5px] text-ink-600">
          <span>Preferences persist locally in this workspace.</span>
          <div className="flex-1" />
          <span>ura:settings:v1</span>
        </div>
      </div>
    </div>
  );
}

function LayoutIcon() {
  return (
    <svg
      className="size-3.5"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.4"
      aria-hidden="true"
    >
      <rect x="1.5" y="1.5" width="13" height="13" rx="1.5" />
      <path d="M5.5 1.5v13M5.5 8h9" />
    </svg>
  );
}
