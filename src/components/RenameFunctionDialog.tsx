import { useEffect, useRef, useState } from "react";
import { Pencil, Trash2, X } from "lucide-react";
import { functionAt } from "../lib/api";
import type { FunctionDetail } from "../lib/types";
import { formatHex } from "../lib/format";
import { useSession } from "../state/session";

export function RenameFunctionDialog() {
  const { renameRequest, renameFunction, closeRename } = useSession();
  const [value, setValue] = useState("");
  const [detail, setDetail] = useState<FunctionDetail | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!renameRequest) return;
    let cancelled = false;
    setDetail(null);
    functionAt(renameRequest.address)
      .then((result) => {
        if (cancelled) return;
        setDetail(result);
        setValue(result?.customName ?? "");
      })
      .catch(() => {
        if (!cancelled) setValue("");
      });
    return () => {
      cancelled = true;
    };
  }, [renameRequest]);

  useEffect(() => {
    if (!renameRequest) return;
    const frame = requestAnimationFrame(() => {
      inputRef.current?.focus();
      inputRef.current?.select();
    });
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeRename();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("keydown", onKey);
    };
  }, [renameRequest, closeRename]);

  if (!renameRequest) return null;

  const address = renameRequest.address;
  const displayName = detail?.name ?? address;
  const hasCustomName = Boolean(detail?.customName);

  const submit = () => {
    renameFunction(address, value);
    closeRename();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/55 px-4 pt-[18vh] backdrop-blur-[2px]"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) closeRename();
      }}
    >
      <form
        className="w-full max-w-[420px] overflow-hidden rounded-xl border border-edge-strong bg-obsidian-850 shadow-[0_24px_80px_rgba(0,0,0,0.65)]"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <div className="flex items-center gap-2 border-b border-edge bg-obsidian-800 px-3.5 py-2.5">
          <Pencil className="size-4 text-accent-400" />
          <span className="flex-1 text-[12px] font-semibold uppercase tracking-[0.14em] text-ink-300">
            Rename function
          </span>
          <span className="kbd">Esc</span>
          <button
            type="button"
            className="icon-btn size-6"
            onClick={closeRename}
            aria-label="Close rename dialog"
          >
            <X className="size-3.5" />
          </button>
        </div>

        <div className="space-y-3 p-4">
          <div className="flex items-center justify-between gap-2 font-mono text-[10.5px]">
            <span className="text-ink-500">{formatHex(address, 16)}</span>
            <span className="truncate text-ink-300" title={displayName}>
              {displayName}
            </span>
          </div>
          <input
            ref={inputRef}
            className="input"
            value={value}
            maxLength={256}
            spellCheck={false}
            placeholder="Custom function name"
            aria-label="Function name"
            onChange={(event) => setValue(event.target.value)}
          />
          <div className="text-[10px] leading-relaxed text-ink-500">
            Custom names are stored in the open URA project and override the
            imported symbol. Leave the field empty to remove the custom name.
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="btn h-7 px-2 text-[11px] text-red-300 hover:border-red-500/40 hover:bg-red-500/10"
              disabled={!hasCustomName}
              onClick={() => {
                renameFunction(address, "");
                closeRename();
              }}
              title="Remove custom name"
            >
              <Trash2 className="size-3.5" />
              Remove
            </button>
            <div className="flex-1" />
            <button
              type="button"
              className="btn h-7 px-2.5 text-[11px]"
              onClick={closeRename}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary h-7 px-2.5 text-[11px]"
              disabled={value.trim().length > 256}
            >
              Save name
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
