import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { LogEntry, LogLevel } from "../lib/types";

const MAX_MESSAGES = 400;

function makeLogEntry(id: number, level: LogLevel, text: string): LogEntry {
  return {
    id,
    time: new Date().toLocaleTimeString([], { hour12: false }),
    level,
    text,
  };
}

interface MessagesContextValue {
  messages: LogEntry[];
  log: (level: LogLevel, text: string) => void;
  clear: () => void;
  toast: { level: LogLevel; text: string } | null;
  dismissToast: () => void;
}

const MessagesContext = createContext<MessagesContextValue | null>(null);

export function MessagesProvider({ children }: { children: React.ReactNode }) {
  const nextId = useRef(1);
  const [messages, setMessages] = useState<LogEntry[]>(() => [
    makeLogEntry(nextId.current++, "info", "URA ready. Open a binary to begin analysis."),
  ]);
  const [toast, setToast] = useState<{ level: LogLevel; text: string } | null>(null);

  const log = useCallback((level: LogLevel, text: string) => {
    setMessages((previous) => {
      const next = [...previous, makeLogEntry(nextId.current++, level, text)];
      return next.length > MAX_MESSAGES
        ? next.slice(next.length - MAX_MESSAGES)
        : next;
    });
    if (level === "error") setToast({ level, text });
  }, []);

  const clear = useCallback(() => setMessages([]), []);
  const dismissToast = useCallback(() => setToast(null), []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 6500);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const value = useMemo(
    () => ({ messages, log, clear, toast, dismissToast }),
    [messages, log, clear, toast, dismissToast],
  );

  return (
    <MessagesContext.Provider value={value}>{children}</MessagesContext.Provider>
  );
}

export function useMessages(): MessagesContextValue {
  const context = useContext(MessagesContext);
  if (!context) throw new Error("useMessages must be used inside MessagesProvider");
  return context;
}
