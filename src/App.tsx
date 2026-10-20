import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Hash,
  Info,
  Layers,
  ListTree,
  ScanSearch,
  Trash2,
  X,
} from "lucide-react";
import { CommandPalette } from "./components/CommandPalette";
import { DisassemblyView } from "./components/DisassemblyView";
import { Explorer } from "./components/Explorer";
import { HexView } from "./components/HexView";
import { Inspector } from "./components/Inspector";
import { Overview } from "./components/Overview";
import { StatusBar } from "./components/StatusBar";
import { StringsView } from "./components/StringsView";
import { Toolbar } from "./components/Toolbar";
import { Welcome } from "./components/Welcome";
import {
  closeBinary,
  createAnalysisProject,
  deleteAnnotation,
  errorMessage,
  extractStrings,
  openAnalysisProject,
  openBinary,
  saveAnnotation,
  setProjectAddress,
  takeStartupPath,
} from "./lib/api";
import {
  addressToOffset,
  normalizeAddress,
  resolveNavigation,
  sectionForAddress,
} from "./lib/format";
import type {
  BinaryOpenResult,
  LogEntry,
  LogLevel,
  NavigateFn,
  NavigationTarget,
  ProjectSnapshot,
  Selection,
  StringScanResult,
  ViewKind,
} from "./lib/types";

const viewLabels: Record<ViewKind, string> = {
  disassembly: "Disassembly",
  hex: "Hex",
  strings: "Strings",
  overview: "Overview",
};

const viewTabs: Array<{
  id: ViewKind;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: "disassembly", label: "Disassembly", icon: ListTree },
  { id: "hex", label: "Hex", icon: Hash },
  { id: "strings", label: "Strings", icon: ScanSearch },
  { id: "overview", label: "Overview", icon: Layers },
];

let nextMessageId = 1;

function makeLogEntry(level: LogLevel, text: string): LogEntry {
  return {
    id: nextMessageId++,
    time: new Date().toLocaleTimeString([], { hour12: false }),
    level,
    text,
  };
}

function MessageIcon({ level }: { level: LogLevel }) {
  if (level === "error") return <AlertCircle className="size-3.5 text-red-400" />;
  if (level === "warning")
    return <AlertTriangle className="size-3.5 text-amber-400" />;
  if (level === "success")
    return <CheckCircle2 className="size-3.5 text-emerald-400" />;
  return <Info className="size-3.5 text-accent-400" />;
}

export default function App() {
  const [binary, setBinary] = useState<BinaryOpenResult | null>(null);
  const [view, setView] = useState<ViewKind>("disassembly");
  const [selection, setSelection] = useState<Selection | null>(null);
  const [navigation, setNavigation] = useState<NavigationTarget>({ nonce: 0 });
  const [project, setProject] = useState<ProjectSnapshot | null>(null);
  const [projectPath, setProjectPath] = useState<string | null>(null);
  const [strings, setStrings] = useState<StringScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [messages, setMessages] = useState<LogEntry[]>(() => [
    makeLogEntry("info", "URA ready. Open a binary to begin analysis."),
  ]);
  const [messagesOpen, setMessagesOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [toast, setToast] = useState<{ level: LogLevel; text: string } | null>(
    null,
  );

  const messageEndRef = useRef<HTMLDivElement>(null);
  const lastSavedAddress = useRef<string | null>(null);

  const log = useCallback((level: LogLevel, text: string) => {
    setMessages((previous) => {
      const next = [...previous, makeLogEntry(level, text)];
      return next.length > 300 ? next.slice(next.length - 300) : next;
    });
    if (level === "error") setToast({ level, text });
  }, []);

  const annotations = project?.annotations ?? [];

  const applyBinary = useCallback(
    (result: BinaryOpenResult, preferredAddress?: string | null) => {
      setBinary(result);
      setStrings(null);
      const target =
        normalizeAddress(preferredAddress ?? null) ??
        normalizeAddress(result.info.entryPoint);
      setSelection(
        target
          ? {
              address: target,
              fileOffset: addressToOffset(result.sections, target),
            }
          : null,
      );
      setNavigation({ address: target, nonce: Date.now() });
      setView("disassembly");
    },
    [],
  );

  const loadBinaryPath = useCallback(
    async (path: string) => {
      setBusy("Analyzing binary…");
      try {
        const result = await openBinary(path);
        applyBinary(result);
        log(
          "success",
          `Loaded ${result.info.fileName} — ${result.info.format} ${result.info.architecture}, ${result.sections.length} sections, ${result.symbols.length} symbols.`,
        );
        if (result.info.warnings.length > 0) {
          log("warning", result.info.warnings.join(" "));
        }
        if (project && result.info.sha256 !== project.project.binaryHash) {
          log(
            "warning",
            "The loaded binary does not match the open project's recorded hash.",
          );
        }
      } catch (err) {
        log("error", `Failed to open binary: ${errorMessage(err)}`);
      } finally {
        setBusy(null);
      }
    },
    [applyBinary, log, project],
  );

  const handleOpenBinary = useCallback(async () => {
    try {
      const picked = await open({
        title: "Open binary",
        multiple: false,
        directory: false,
        filters: [
          {
            name: "Executable images",
            extensions: ["exe", "dll", "sys", "elf", "so", "bin", "dylib", "out"],
          },
          { name: "All files", extensions: ["*"] },
        ],
      });
      if (typeof picked !== "string") return;
      await loadBinaryPath(picked);
    } catch (err) {
      log("error", `Failed to open file dialog: ${errorMessage(err)}`);
    }
  }, [loadBinaryPath, log]);

  useEffect(() => {
    takeStartupPath()
      .then((path) => {
        if (path) void loadBinaryPath(path);
      })
      .catch((err) => {
        log("warning", `Unable to read startup path: ${errorMessage(err)}`);
      });
  }, [loadBinaryPath, log]);

  const handleCloseBinary = useCallback(() => {
    void closeBinary();
    setBinary(null);
    setSelection(null);
    setStrings(null);
    setNavigation({ nonce: Date.now() });
    log("info", "Binary closed.");
  }, [log]);

  const handleOpenProject = useCallback(async () => {
    try {
      const picked = await open({
        title: "Open URA project",
        multiple: false,
        directory: false,
        filters: [{ name: "URA project", extensions: ["ura"] }],
      });
      if (typeof picked !== "string") return;
      setBusy("Opening project…");
      const snapshot = await openAnalysisProject(picked);
      setProject(snapshot);
      setProjectPath(picked);
      lastSavedAddress.current = normalizeAddress(
        snapshot.project.selectedAddress,
      );
      log(
        "success",
        `Opened project “${snapshot.project.name}” (${snapshot.annotations.length} annotations).`,
      );

      if (snapshot.binaryStatus === "missing") {
        setBinary(null);
        setStrings(null);
        setSelection(null);
        log(
          "warning",
          `Source binary is missing: ${snapshot.project.binaryPath}`,
        );
        return;
      }

      setBusy("Loading project binary…");
      const result = await openBinary(snapshot.project.binaryPath);
      applyBinary(result, snapshot.project.selectedAddress);
      if (result.info.sha256 !== snapshot.project.binaryHash) {
        setProject({ ...snapshot, binaryStatus: "modified" });
        log(
          "warning",
          "Project binary hash differs from the recorded analysis — annotations may be stale.",
        );
      } else {
        log(
          "info",
          `Loaded ${result.info.fileName} · binary verified against project.`,
        );
      }
    } catch (err) {
      log("error", `Failed to open project: ${errorMessage(err)}`);
    } finally {
      setBusy(null);
    }
  }, [applyBinary, log]);

  const handleNewProject = useCallback(async () => {
    if (!binary) {
      log("warning", "Open a binary before creating a project.");
      return;
    }
    try {
      const fallbackName =
        binary.info.fileName.replace(/\.[^./\\]+$/, "") || "analysis";
      const picked = await save({
        title: "Create URA project",
        defaultPath: `${fallbackName}.ura`,
        filters: [{ name: "URA project", extensions: ["ura"] }],
      });
      if (typeof picked !== "string" || !picked) return;
      const projectFile = picked.toLowerCase().endsWith(".ura")
        ? picked
        : `${picked}.ura`;
      setBusy("Creating project…");
      const info = await createAnalysisProject(projectFile, fallbackName);
      setProject({
        project: info,
        annotations: [],
        binaryStatus: "unchanged",
      });
      setProjectPath(projectFile);
      lastSavedAddress.current = null;
      log("success", `Created project “${info.name}”.`);
      setMessagesOpen(true);
    } catch (err) {
      log("error", `Failed to create project: ${errorMessage(err)}`);
    } finally {
      setBusy(null);
    }
  }, [binary, log]);

  const handleSaveAnnotation = useCallback(
    async (address: string, label: string, note: string) => {
      if (!projectPath) {
        log("warning", "Create or open a project to save annotations.");
        return;
      }
      setBusy("Saving annotation…");
      try {
        const saved = await saveAnnotation(
          projectPath,
          address,
          label.trim() || null,
          note,
        );
        setProject((previous) =>
          previous
            ? {
                ...previous,
                annotations: [
                  ...previous.annotations.filter(
                    (annotation) =>
                      normalizeAddress(annotation.address) !==
                      normalizeAddress(saved.address),
                  ),
                  saved,
                ],
              }
            : previous,
        );
        log(
          "success",
          `Saved annotation at ${saved.address}${saved.label ? ` — ${saved.label}` : ""}.`,
        );
      } catch (err) {
        log("error", `Failed to save annotation: ${errorMessage(err)}`);
      } finally {
        setBusy(null);
      }
    },
    [projectPath, log],
  );

  const handleDeleteAnnotation = useCallback(
    async (id: number) => {
      if (!projectPath) return;
      setBusy("Deleting annotation…");
      try {
        await deleteAnnotation(projectPath, id);
        setProject((previous) =>
          previous
            ? {
                ...previous,
                annotations: previous.annotations.filter(
                  (annotation) => annotation.id !== id,
                ),
              }
            : previous,
        );
        log("info", `Deleted annotation #${id}.`);
      } catch (err) {
        log("error", `Failed to delete annotation: ${errorMessage(err)}`);
      } finally {
        setBusy(null);
      }
    },
    [projectPath, log],
  );

  const runScan = useCallback(
    async (minLength: number, ascii: boolean, utf16: boolean) => {
      setScanning(true);
      try {
        const result = await extractStrings(minLength, ascii, utf16);
        setStrings(result);
        log(
          "info",
          `String scan: ${result.strings.length} results (${result.asciiCount} ASCII, ${result.utf16Count} UTF-16).`,
        );
      } catch (err) {
        log("error", `String scan failed: ${errorMessage(err)}`);
      } finally {
        setScanning(false);
      }
    },
    [log],
  );

  useEffect(() => {
    if (!binary) {
      setStrings(null);
      return;
    }
    let cancelled = false;
    setScanning(true);
    extractStrings(4, true, true)
      .then((result) => {
        if (cancelled) return;
        setStrings(result);
        log(
          "info",
          `Extracted ${result.strings.length} strings (${result.asciiCount} ASCII, ${result.utf16Count} UTF-16).`,
        );
      })
      .catch((err) => {
        if (cancelled) return;
        log("warning", `Automatic string scan failed: ${errorMessage(err)}`);
      })
      .finally(() => {
        if (!cancelled) setScanning(false);
      });
    return () => {
      cancelled = true;
    };
  }, [binary, log]);

  useEffect(() => {
    lastSavedAddress.current = null;
  }, [projectPath]);

  useEffect(() => {
    if (!projectPath || !selection?.address) return;
    const normalized = normalizeAddress(selection.address);
    if (!normalized || lastSavedAddress.current === normalized) return;
    const timeout = window.setTimeout(() => {
      setProjectAddress(projectPath, normalized)
        .then(() => {
          lastSavedAddress.current = normalized;
          setProject((previous) =>
            previous
              ? {
                  ...previous,
                  project: {
                    ...previous.project,
                    selectedAddress: normalized,
                  },
                }
              : previous,
          );
        })
        .catch((err) => {
          log("warning", `Unable to store selection: ${errorMessage(err)}`);
        });
    }, 700);
    return () => window.clearTimeout(timeout);
  }, [selection?.address, projectPath, log]);

  const navigate = useCallback<NavigateFn>(
    (target, nextView) => {
      const sections = binary?.sections ?? [];
      const resolved = resolveNavigation(
        sections,
        target.address,
        target.fileOffset,
      );
      if (resolved.address == null && resolved.fileOffset == null) {
        log("warning", "That target is not mapped in the loaded binary.");
        return;
      }
      setSelection({
        address: resolved.address,
        fileOffset: resolved.fileOffset,
      });
      setNavigation({
        address: resolved.address,
        fileOffset: resolved.fileOffset,
        nonce: Date.now(),
      });
      const section = resolved.address
        ? sectionForAddress(sections, resolved.address)
        : null;
      const inferred =
        nextView ??
        (resolved.address && section
          ? section.executable
            ? "disassembly"
            : "hex"
          : resolved.fileOffset
            ? "hex"
            : undefined);
      if (inferred) setView(inferred);
    },
    [binary, log],
  );

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing =
        target != null &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.tagName === "SELECT" ||
          target.isContentEditable);
      const mod = event.ctrlKey || event.metaKey;
      if (mod && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen(true);
        return;
      }
      if (mod && event.key.toLowerCase() === "o") {
        event.preventDefault();
        if (event.shiftKey) void handleOpenProject();
        else void handleOpenBinary();
        return;
      }
      if (mod && event.key.toLowerCase() === "n") {
        event.preventDefault();
        void handleNewProject();
        return;
      }
      if (mod && ["1", "2", "3", "4"].includes(event.key)) {
        event.preventDefault();
        if (binary) {
          setView(viewTabs[Number(event.key) - 1].id);
        }
        return;
      }
      if (!typing && event.key === "Escape") {
        setPaletteOpen(false);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [binary, handleNewProject, handleOpenBinary, handleOpenProject]);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(null), 6000);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  useEffect(() => {
    if (!messagesOpen) return;
    messageEndRef.current?.scrollIntoView({ block: "end" });
  }, [messages.length, messagesOpen]);

  const binaryStatus = project?.binaryStatus ?? null;

  const content = useMemo(() => {
    if (!binary) {
      return (
        <Welcome
          onOpenBinary={handleOpenBinary}
          onOpenProject={handleOpenProject}
          hasProjectSupport
        />
      );
    }
    switch (view) {
      case "disassembly":
        return (
          <DisassemblyView
            binary={binary}
            target={navigation}
            selection={selection}
            annotations={annotations}
            onSelect={setSelection}
            onNavigate={navigate}
            onLog={log}
          />
        );
      case "hex":
        return (
          <HexView
            binary={binary}
            target={navigation}
            selection={selection}
            onSelect={setSelection}
            onNavigate={navigate}
            onLog={log}
          />
        );
      case "strings":
        return (
          <StringsView
            binary={binary}
            strings={strings}
            scanning={scanning}
            selection={selection}
            onScan={runScan}
            onNavigate={navigate}
          />
        );
      case "overview":
        return (
          <Overview
            binary={binary}
            project={project?.project ?? null}
            onNavigate={navigate}
          />
        );
      default:
        return null;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    binary,
    view,
    navigation,
    selection,
    annotations,
    strings,
    scanning,
    project,
    navigate,
    log,
    runScan,
    handleOpenBinary,
    handleOpenProject,
  ]);

  return (
    <div className="flex h-full flex-col overflow-hidden bg-obsidian-950">
      <Toolbar
        binary={binary}
        project={project?.project ?? null}
        projectPath={projectPath}
        busy={busy}
        onOpenBinary={handleOpenBinary}
        onCloseBinary={handleCloseBinary}
        onNewProject={handleNewProject}
        onOpenProject={handleOpenProject}
        onGoTo={() => setPaletteOpen(true)}
      />

      <div className="flex min-h-0 flex-1">
        {binary ? (
          <>
            <Explorer
              binary={binary}
              annotations={annotations}
              selection={selection}
              onNavigate={navigate}
            />
            <main className="flex min-w-0 flex-1 flex-col bg-obsidian-900">
              <div className="flex h-9 shrink-0 items-center border-b border-edge bg-obsidian-900 px-1">
                {viewTabs.map((tab) => {
                  const Icon = tab.icon;
                  const active = view === tab.id;
                  return (
                    <button
                      key={tab.id}
                      className={`tab ${active ? "tab-active" : ""}`}
                      onClick={() => setView(tab.id)}
                      title={`${tab.label} (Ctrl+${viewTabs.indexOf(tab) + 1})`}
                    >
                      <Icon className="size-3.5" />
                      {tab.label}
                      {tab.id === "strings" && strings && (
                        <span className="ml-0.5 rounded bg-obsidian-700 px-1 font-mono text-[9px] text-ink-400">
                          {strings.strings.length}
                        </span>
                      )}
                    </button>
                  );
                })}
                <div className="flex-1" />
                {binary.info.warnings.length > 0 && (
                  <div className="mr-2 flex items-center gap-1 text-[10.5px] text-amber-400/80">
                    <AlertTriangle className="size-3" />
                    {binary.info.warnings.length} warning
                    {binary.info.warnings.length === 1 ? "" : "s"}
                  </div>
                )}
                <div className="mr-2 hidden font-mono text-[9.5px] text-ink-600 lg:block">
                  {binary.info.format} · {binary.info.architecture} ·{" "}
                  {binary.info.bitness}-bit
                </div>
              </div>
              <div className="min-h-0 flex-1">{content}</div>
            </main>
            <Inspector
              binary={binary}
              selection={selection}
              annotations={annotations}
              project={project?.project ?? null}
              projectPath={projectPath}
              binaryStatus={binaryStatus}
              busy={busy != null}
              onSaveAnnotation={handleSaveAnnotation}
              onDeleteAnnotation={handleDeleteAnnotation}
              onNavigate={navigate}
              onNewProject={handleNewProject}
            />
          </>
        ) : (
          <div className="min-w-0 flex-1">{content}</div>
        )}
      </div>

      {messagesOpen && (
        <div className="flex h-36 shrink-0 flex-col border-t border-edge bg-obsidian-850">
          <div className="flex h-6 shrink-0 items-center justify-between border-b border-edge bg-obsidian-800 px-2.5">
            <span className="text-[9.5px] font-semibold uppercase tracking-[0.16em] text-ink-400">
              Messages
            </span>
            <div className="flex items-center gap-1">
              <button
                className="icon-btn size-5"
                title="Clear messages"
                onClick={() => setMessages([])}
              >
                <Trash2 className="size-3" />
              </button>
              <button
                className="icon-btn size-5"
                title="Close messages"
                onClick={() => setMessagesOpen(false)}
              >
                <X className="size-3" />
              </button>
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-auto py-1 font-mono text-[10.5px]">
            {messages.length === 0 ? (
              <div className="px-3 py-2 text-ink-600">No messages.</div>
            ) : (
              messages.map((entry) => (
                <div
                  key={entry.id}
                  className="flex items-start gap-2 px-2.5 py-0.5 leading-relaxed hover:bg-obsidian-800/60"
                >
                  <span className="shrink-0 text-ink-600">{entry.time}</span>
                  <MessageIcon level={entry.level} />
                  <span
                    className={
                      entry.level === "error"
                        ? "text-red-300/90"
                        : entry.level === "warning"
                          ? "text-amber-300/90"
                          : entry.level === "success"
                            ? "text-emerald-300/90"
                            : "text-ink-300"
                    }
                  >
                    {entry.text}
                  </span>
                </div>
              ))
            )}
            <div ref={messageEndRef} />
          </div>
        </div>
      )}

      <StatusBar
        binary={binary}
        project={project?.project ?? null}
        projectPath={projectPath}
        binaryStatus={binaryStatus}
        selection={selection}
        viewLabel={binary ? viewLabels[view] : "Welcome"}
        messageCount={messages.length}
        messagesOpen={messagesOpen}
        onToggleMessages={() => setMessagesOpen((value) => !value)}
      />

      <CommandPalette
        open={paletteOpen}
        binary={binary}
        annotations={annotations}
        onClose={() => setPaletteOpen(false)}
        onOpenBinary={handleOpenBinary}
        onNewProject={handleNewProject}
        onOpenProject={handleOpenProject}
        onNavigate={navigate}
        onSwitchView={setView}
        onScanStrings={() => void runScan(4, true, true)}
      />

      {toast && (
        <div className="fixed bottom-11 right-4 z-40 flex max-w-md items-start gap-2 rounded-lg border border-red-500/35 bg-obsidian-800 px-3 py-2 shadow-2xl">
          <AlertCircle className="mt-0.5 size-4 shrink-0 text-red-400" />
          <div className="min-w-0 flex-1">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-red-300">
              Error
            </div>
            <div className="mt-0.5 break-words text-[11.5px] leading-snug text-ink-200">
              {toast.text}
            </div>
          </div>
          <button
            className="icon-btn size-5 shrink-0"
            onClick={() => setToast(null)}
            aria-label="Dismiss error"
          >
            <X className="size-3" />
          </button>
        </div>
      )}
    </div>
  );
}
