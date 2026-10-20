import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Clipboard,
  Info,
  Search,
  Trash2,
} from "lucide-react";
import type { LogLevel } from "../lib/types";
import { useMessages } from "../state/messages";

type LevelFilter = "all" | "error" | "warning";

function MessageIcon({ level }: { level: LogLevel }) {
  if (level === "error")
    return <AlertCircle className="size-3.5 shrink-0 text-red-400" />;
  if (level === "warning")
    return <AlertTriangle className="size-3.5 shrink-0 text-amber-400" />;
  if (level === "success")
    return <CheckCircle2 className="size-3.5 shrink-0 text-emerald-400" />;
  return <Info className="size-3.5 shrink-0 text-accent-400" />;
}

function messageTone(level: LogLevel): string {
  if (level === "error") return "text-red-300/90";
  if (level === "warning") return "text-amber-300/90";
  if (level === "success") return "text-emerald-300/90";
  return "text-ink-300";
}

export function MessagesPanel() {
  const { messages, clear } = useMessages();
  const [filter, setFilter] = useState("");
  const [level, setLevel] = useState<LevelFilter>("all");
  const endRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return messages.filter((entry) => {
      if (level !== "all" && entry.level !== level) return false;
      if (!needle) return true;
      return entry.text.toLowerCase().includes(needle);
    });
  }, [messages, filter, level]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [filtered.length, level]);

  const copyAll = () => {
    const text = filtered
      .map((entry) => `${entry.time} [${entry.level.toUpperCase()}] ${entry.text}`)
      .join("\n");
    void navigator.clipboard.writeText(text);
  };

  return (
    <div className="view-root">
      <div className="view-toolbar gap-2">
        <span className="font-semibold uppercase tracking-[0.14em] text-ink-500">
          Log
        </span>
        <span className="text-ink-600">|</span>
        <span className="text-ink-500">
          {filtered.length.toLocaleString()} / {messages.length.toLocaleString()}
        </span>
        <div className="relative ml-2 min-w-32 max-w-64 flex-1">
          <Search className="pointer-events-none absolute left-1.5 top-1/2 size-3 -translate-y-1/2 text-ink-500" />
          <input
            className="input h-6 pl-6 font-sans text-[10.5px]"
            placeholder="Filter messages…"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            spellCheck={false}
          />
        </div>
        <div className="flex overflow-hidden rounded border border-edge-strong">
          {(["all", "warning", "error"] as LevelFilter[]).map((value) => (
            <button
              key={value}
              className={`h-6 px-1.5 font-sans text-[10px] transition-colors ${
                level === value
                  ? "bg-accent-500/15 text-accent-300"
                  : "bg-obsidian-800 text-ink-500 hover:text-ink-300"
              }`}
              onClick={() => setLevel(value)}
            >
              {value === "all" ? "All" : value === "warning" ? "Warnings" : "Errors"}
            </button>
          ))}
        </div>
        <div className="flex-1" />
        <button
          className="icon-btn size-6"
          title="Copy visible messages"
          onClick={copyAll}
          disabled={filtered.length === 0}
        >
          <Clipboard className="size-3" />
        </button>
        <button
          className="icon-btn size-6"
          title="Clear messages"
          onClick={clear}
          disabled={messages.length === 0}
        >
          <Trash2 className="size-3" />
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto py-0.5 font-mono text-[10.5px]">
        {filtered.length === 0 ? (
          <div className="px-3 py-3 text-ink-600">
            {messages.length === 0 ? "No messages." : "No messages match the filter."}
          </div>
        ) : (
          filtered.map((entry) => (
            <div
              key={entry.id}
              className="flex items-start gap-2 px-2.5 py-0.5 leading-relaxed hover:bg-obsidian-800/60"
            >
              <span className="w-14 shrink-0 text-right text-ink-600">
                {entry.time}
              </span>
              <MessageIcon level={entry.level} />
              <span className={`min-w-0 break-words ${messageTone(entry.level)}`}>
                {entry.text}
              </span>
            </div>
          ))
        )}
        <div ref={endRef} />
      </div>
    </div>
  );
}
