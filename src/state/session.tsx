import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  analyzeBinary,
  cancelAnalysis as cancelNativeAnalysis,
  closeBinary as closeNativeBinary,
  createAnalysisProject,
  createManualFunction,
  deleteAnnotation as deleteNativeAnnotation,
  errorMessage,
  exportAnnotations as exportNativeAnnotations,
  extractStrings,
  functionAt,
  openAnalysisProject,
  openBinary as openNativeBinary,
  removeManualFunction,
  renameFunction as renameNativeFunction,
  saveAnnotation as saveNativeAnnotation,
  saveViewState as saveNativeViewState,
  setProjectAddress,
  takeStartupPath,
} from "../lib/api";
import {
  WORKSPACE_PANEL_TITLES,
  type WorkspacePanelId,
} from "../lib/panels";
import {
  addressToOffset,
  normalizeAddress,
  resolveNavigation,
  sectionForAddress,
} from "../lib/format";
import type {
  AnalysisProgress,
  AnalysisSummary,
  Annotation,
  BinaryOpenResult,
  FunctionDetail,
  NavigateFn,
  NavigationTarget,
  ProjectSnapshot,
  Selection,
  StringScanResult,
  ViewKind,
} from "../lib/types";
import { useMessages } from "./messages";
import { useWorkspace } from "./workspace";

interface SessionContextValue {
  binary: BinaryOpenResult | null;
  project: ProjectSnapshot | null;
  projectPath: string | null;
  annotations: Annotation[];
  selection: Selection | null;
  navigation: NavigationTarget;
  strings: StringScanResult | null;
  scanning: boolean;
  busy: string | null;
  analysis: AnalysisSummary | null;
  analysisRunning: boolean;
  analysisProgress: AnalysisProgress | null;
  analysisError: string | null;
  functionRevision: number;
  currentFunction: FunctionDetail | null;
  cfgAddress: string | null;
  renameRequest: { address: string } | null;
  canGoBack: boolean;
  canGoForward: boolean;
  setSelection: (selection: Selection | null) => void;
  navigate: NavigateFn;
  goBack: () => void;
  goForward: () => void;
  createUserFunction: (address: string) => void;
  deleteUserFunction: (address: string) => void;
  exportProjectAnnotations: () => void;
  openBinaryDialog: () => void;
  openBinaryPath: (path: string) => void;
  closeBinary: () => void;
  openProjectDialog: () => void;
  newProject: () => void;
  saveAnnotation: (address: string, label: string, note: string) => void;
  deleteAnnotation: (id: number) => void;
  scanStrings: (minLength: number, ascii: boolean, utf16: boolean) => void;
  startAnalysis: () => void;
  cancelAnalysis: () => void;
  renameFunction: (address: string, name: string) => void;
  openCfg: (address?: string | null) => void;
  openXrefs: (address?: string | null) => void;
  requestRename: (address?: string | null) => void;
  closeRename: () => void;
  focusView: (view: ViewKind) => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

interface HistoryEntry {
  address: string | null;
  fileOffset: string | null;
}

interface SavedViewState {
  version: 1;
  address: string | null;
  fileOffset: string | null;
  cfgAddress: string | null;
  functionAddress: string | null;
  history: HistoryEntry[];
  historyIndex: number;
  activePanel: WorkspacePanelId | null;
  openPanels: WorkspacePanelId[];
}

const MAX_HISTORY = 100;

function normalizeHistoryEntry(
  entry: Partial<HistoryEntry> | null | undefined,
): HistoryEntry | null {
  if (!entry) return null;
  const address = normalizeAddress(entry.address ?? null);
  const fileOffset = normalizeAddress(entry.fileOffset ?? null);
  if (!address && !fileOffset) return null;
  return { address, fileOffset };
}

function isWorkspacePanel(value: unknown): value is WorkspacePanelId {
  return (
    typeof value === "string" &&
    Object.prototype.hasOwnProperty.call(WORKSPACE_PANEL_TITLES, value)
  );
}

function parseViewState(raw: string | null | undefined): SavedViewState | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<SavedViewState>;
    if (!parsed || typeof parsed !== "object") return null;
    const history = Array.isArray(parsed.history)
      ? parsed.history
          .map((entry) => normalizeHistoryEntry(entry))
          .filter((entry): entry is HistoryEntry => entry != null)
      : [];
    const historyIndex =
      typeof parsed.historyIndex === "number"
        ? Math.min(Math.max(0, parsed.historyIndex), Math.max(0, history.length - 1))
        : history.length - 1;
    return {
      version: 1,
      address: normalizeAddress(parsed.address ?? null),
      fileOffset: normalizeAddress(parsed.fileOffset ?? null),
      cfgAddress: normalizeAddress(parsed.cfgAddress ?? null),
      functionAddress: normalizeAddress(parsed.functionAddress ?? null),
      history,
      historyIndex,
      activePanel: isWorkspacePanel(parsed.activePanel)
        ? parsed.activePanel
        : null,
      openPanels: Array.isArray(parsed.openPanels)
        ? parsed.openPanels.filter(isWorkspacePanel)
        : [],
    };
  } catch {
    return null;
  }
}

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const { log } = useMessages();
  const {
    focusView: workspaceFocusView,
    showPanel,
    activePanelId,
    openPanels,
    setLayoutScope,
  } = useWorkspace();

  const [binary, setBinary] = useState<BinaryOpenResult | null>(null);
  const [project, setProject] = useState<ProjectSnapshot | null>(null);
  const [projectPath, setProjectPath] = useState<string | null>(null);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [navigation, setNavigation] = useState<NavigationTarget>({ nonce: 0 });
  const [strings, setStrings] = useState<StringScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisSummary | null>(null);
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [analysisProgress, setAnalysisProgress] =
    useState<AnalysisProgress | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [functionRevision, setFunctionRevision] = useState(0);
  const [currentFunction, setCurrentFunction] = useState<FunctionDetail | null>(
    null,
  );
  const [cfgAddress, setCfgAddress] = useState<string | null>(null);
  const [renameRequest, setRenameRequest] = useState<{
    address: string;
  } | null>(null);

  const lastSavedAddress = useRef<string | null>(null);
  const projectRef = useRef<ProjectSnapshot | null>(null);
  const analysisRunId = useRef(0);
  const analysisInFlight = useRef(false);
  const historyRef = useRef<{ entries: HistoryEntry[]; index: number }>({
    entries: [],
    index: -1,
  });
  const [historyToken, setHistoryToken] = useState(0);
  const [viewRestoreToken, setViewRestoreToken] = useState(0);
  const restoringView = useRef(false);
  projectRef.current = project;

  const annotations = project?.annotations ?? [];

  const focusView = useCallback(
    (view: ViewKind) => workspaceFocusView(view),
    [workspaceFocusView],
  );

  const applyBinary = useCallback(
    (result: BinaryOpenResult, preferredAddress?: string | null) => {
      setBinary(result);
      setStrings(null);
      setAnalysis(null);
      setAnalysisProgress(null);
      setAnalysisError(null);
      setAnalysisRunning(false);
      setCurrentFunction(null);
      setCfgAddress(null);
      setRenameRequest(null);
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
      const fileOffset = target ? addressToOffset(result.sections, target) : null;
      historyRef.current = {
        entries: target || fileOffset ? [{ address: target, fileOffset }] : [],
        index: target || fileOffset ? 0 : -1,
      };
      setHistoryToken((value) => value + 1);
      focusView("disassembly");
    },
    [focusView],
  );

  const loadBinaryPath = useCallback(
    async (path: string) => {
      setBusy("Analyzing binary…");
      try {
        const result = await openNativeBinary(path);
        applyBinary(result);
        log(
          "success",
          `Loaded ${result.info.fileName} — ${result.info.format} ${result.info.architecture}, ${result.sections.length} sections, ${result.symbols.length} symbols.`,
        );
        if (result.info.warnings.length > 0) {
          log("warning", result.info.warnings.join(" "));
        }
        const activeProject = projectRef.current;
        if (
          activeProject &&
          result.info.sha256 !== activeProject.project.binaryHash
        ) {
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
    [applyBinary, log],
  );

  const openBinaryDialog = useCallback(() => {
    void (async () => {
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
    })();
  }, [loadBinaryPath, log]);

  useEffect(() => {
    setLayoutScope(projectPath);
  }, [projectPath, setLayoutScope]);

  useEffect(() => {
    takeStartupPath()
      .then((path) => {
        if (path) void loadBinaryPath(path);
      })
      .catch((err) => {
        log("warning", `Unable to read startup path: ${errorMessage(err)}`);
      });
  }, [loadBinaryPath, log]);

  const closeBinary = useCallback(() => {
    void cancelNativeAnalysis().catch(() => undefined);
    void closeNativeBinary();
    setBinary(null);
    setSelection(null);
    setStrings(null);
    setAnalysis(null);
    setAnalysisProgress(null);
    setAnalysisError(null);
    setAnalysisRunning(false);
    setCurrentFunction(null);
    setCfgAddress(null);
    setRenameRequest(null);
    historyRef.current = { entries: [], index: -1 };
    setHistoryToken((value) => value + 1);
    setNavigation({ nonce: Date.now() });
    log("info", "Binary closed.");
  }, [log]);

  const openProjectDialog = useCallback(() => {
    void (async () => {
      try {
        const picked = await open({
          title: "Open URA project",
          multiple: false,
          directory: false,
          filters: [{ name: "URA project", extensions: ["ura"] }],
        });
        if (typeof picked !== "string") return;
        restoringView.current = true;
        setBusy("Opening project…");
        const snapshot = await openAnalysisProject(picked);
        const saved = parseViewState(snapshot.viewState);
        setProject(snapshot);
        setProjectPath(picked);
        projectRef.current = snapshot;
        setFunctionRevision((value) => value + 1);
        log(
          "success",
          `Opened project “${snapshot.project.name}” (${snapshot.annotations.length} annotations, ${snapshot.functionNames.length} custom function names, ${snapshot.manualFunctions.length} user-defined functions).`,
        );

        if (snapshot.binaryStatus === "missing") {
          setBinary(null);
          setStrings(null);
          setSelection(null);
          setNavigation({ nonce: Date.now() });
          log(
            "warning",
            `Source binary is missing: ${snapshot.project.binaryPath}`,
          );
          restoringView.current = false;
          return;
        }

        setBusy("Loading project binary…");
        const result = await openNativeBinary(snapshot.project.binaryPath);
        applyBinary(
          result,
          saved?.address ?? snapshot.project.selectedAddress,
        );
        if (saved) {
          if (saved.history.length > 0) {
            historyRef.current = {
              entries: saved.history,
              index: saved.historyIndex,
            };
            setHistoryToken((value) => value + 1);
          }
          if (saved.cfgAddress) setCfgAddress(saved.cfgAddress);
          if (saved.activePanel) showPanel(saved.activePanel);
        }
        window.setTimeout(() => {
          restoringView.current = false;
          setViewRestoreToken((value) => value + 1);
        }, 500);
        if (result.info.sha256 !== snapshot.project.binaryHash) {
          setProject((previous) =>
            previous ? { ...previous, binaryStatus: "modified" } : previous,
          );
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
        restoringView.current = false;
        log("error", `Failed to open project: ${errorMessage(err)}`);
      } finally {
        setBusy(null);
      }
    })();
  }, [applyBinary, log, showPanel]);

  const newProject = useCallback(() => {
    if (!binary) {
      log("warning", "Open a binary before creating a project.");
      return;
    }
    void (async () => {
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
        const snapshot: ProjectSnapshot = {
          project: info,
          annotations: [],
          functionNames: [],
          manualFunctions: [],
          viewState: null,
          binaryStatus: "unchanged",
        };
        setProject(snapshot);
        setProjectPath(projectFile);
        projectRef.current = snapshot;
        lastSavedAddress.current = null;
        restoringView.current = false;
        log("success", `Created project “${info.name}”.`);
        showPanel("messages");
      } catch (err) {
        log("error", `Failed to create project: ${errorMessage(err)}`);
      } finally {
        setBusy(null);
      }
    })();
  }, [binary, log, showPanel]);

  const saveAnnotation = useCallback(
    (address: string, label: string, note: string) => {
      if (!projectPath) {
        log("warning", "Create or open a project to save annotations.");
        return;
      }
      setBusy("Saving annotation…");
      void (async () => {
        try {
          const saved = await saveNativeAnnotation(
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
      })();
    },
    [projectPath, log],
  );

  const deleteAnnotation = useCallback(
    (id: number) => {
      if (!projectPath) return;
      setBusy("Deleting annotation…");
      void (async () => {
        try {
          await deleteNativeAnnotation(projectPath, id);
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
      })();
    },
    [projectPath, log],
  );

  const scanStrings = useCallback(
    (minLength: number, ascii: boolean, utf16: boolean) => {
      setScanning(true);
      void (async () => {
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
      })();
    },
    [log],
  );

  const startAnalysis = useCallback(() => {
    if (!binary || analysisInFlight.current) return;
    analysisInFlight.current = true;
    const runId = ++analysisRunId.current;
    setAnalysisRunning(true);
    setAnalysis(null);
    setAnalysisError(null);
    setAnalysisProgress({
      stage: "preparing",
      instructions: 0,
      functions: 0,
      blocks: 0,
      currentAddress: null,
    });

    const finish = () => {
      if (analysisRunId.current !== runId) return;
      analysisInFlight.current = false;
      setAnalysisRunning(false);
      setAnalysisProgress(null);
    };

    const attempt = (retries: number) => {
      void analyzeBinary(projectPath)
        .then((summary) => {
          if (analysisRunId.current !== runId) return;
          setAnalysis(summary);
          setFunctionRevision((value) => value + 1);
          const counts = `${summary.functionCount} functions, ${summary.blockCount} blocks, ${summary.xrefCount} xrefs (${summary.dataXrefCount} data) from ${summary.instructionCount} instructions`;
          if (summary.cancelled) {
            log("warning", `Analysis cancelled — partial result: ${counts}.`);
          } else {
            log(
              "success",
              `Analysis complete: ${counts} in ${summary.elapsedMs} ms.`,
            );
          }
          if (summary.truncated) {
            log(
              "warning",
              "Analysis stopped at a configured safety limit; results are partial.",
            );
          }
          if (summary.diagnostics.length > 0) {
            const dropped =
              summary.diagnosticsDropped > 0
                ? ` (+${summary.diagnosticsDropped} dropped)`
                : "";
            log(
              "warning",
              `Analysis diagnostics: ${summary.diagnostics.length}${dropped}. First: ${summary.diagnostics[0].message}`,
            );
          }
          finish();
        })
        .catch((err) => {
          if (analysisRunId.current !== runId) return;
          const message = errorMessage(err);
          if (retries > 0 && /already running/i.test(message)) {
            window.setTimeout(() => {
              if (analysisRunId.current === runId) attempt(retries - 1);
            }, 250);
            return;
          }
          setAnalysisError(message);
          log("error", `Analysis failed: ${message}`);
          finish();
        });
    };

    attempt(8);
  }, [binary, projectPath, log]);

  useEffect(() => {
    analysisRunId.current += 1;
    analysisInFlight.current = false;
    if (!binary) {
      setAnalysisRunning(false);
      setAnalysisProgress(null);
      setCurrentFunction(null);
      setCfgAddress(null);
      return;
    }
    startAnalysis();
  }, [binary, startAnalysis]);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listen<AnalysisProgress>("analysis-progress", (event) => {
      if (!disposed) setAnalysisProgress(event.payload);
    })
      .then((stop) => {
        if (disposed) stop();
        else unlisten = stop;
      })
      .catch((err) => {
        log(
          "warning",
          `Unable to subscribe to analysis progress: ${errorMessage(err)}`,
        );
      });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [log]);

  const cancelAnalysis = useCallback(() => {
    void cancelNativeAnalysis()
      .then((requested) => {
        if (requested) log("info", "Cancelling analysis…");
      })
      .catch((err) => {
        log("warning", `Unable to cancel analysis: ${errorMessage(err)}`);
      });
  }, [log]);

  const renameFunction = useCallback(
    (address: string, name: string) => {
      if (!projectPath) {
        log("warning", "Create or open a project to rename functions.");
        return;
      }
      const normalized = normalizeAddress(address);
      if (!normalized) return;
      const trimmed = name.trim();
      void (async () => {
        try {
          const result = await renameNativeFunction(
            projectPath,
            normalized,
            trimmed,
          );
          log(
            "success",
            result.name
              ? `Renamed ${result.address} to “${result.name}”.`
              : `Removed the custom name for ${result.address}.`,
          );
          setFunctionRevision((value) => value + 1);
        } catch (err) {
          log("error", `Failed to rename function: ${errorMessage(err)}`);
        }
      })();
    },
    [projectPath, log],
  );

  const createUserFunction = useCallback(
    (address: string) => {
      if (!projectPath) {
        log("warning", "Create or open a project to define functions.");
        return;
      }
      const normalized = normalizeAddress(address);
      if (!normalized) return;
      setBusy("Defining function…");
      setAnalysisRunning(true);
      setAnalysisProgress({
        stage: "preparing",
        instructions: 0,
        functions: 0,
        blocks: 0,
        currentAddress: null,
      });
      void createManualFunction(projectPath, normalized)
        .then((summary) => {
          setAnalysis(summary);
          setFunctionRevision((value) => value + 1);
          setSelection({
            address: normalized,
            fileOffset: binary
              ? addressToOffset(binary.sections, normalized)
              : null,
          });
          setNavigation({ address: normalized, nonce: Date.now() });
          focusView("disassembly");
          log(
            "success",
            `Defined function at ${normalized}; analysis now has ${summary.functionCount} functions.`,
          );
        })
        .catch((err) => {
          log("error", `Unable to define function: ${errorMessage(err)}`);
        })
        .finally(() => {
          setAnalysisRunning(false);
          setAnalysisProgress(null);
          setBusy(null);
        });
    },
    [projectPath, binary, log, focusView],
  );

  const deleteUserFunction = useCallback(
    (address: string) => {
      if (!projectPath) {
        log("warning", "Create or open a project to delete functions.");
        return;
      }
      const normalized = normalizeAddress(address);
      if (!normalized) return;
      setBusy("Deleting function…");
      setAnalysisRunning(true);
      setAnalysisProgress({
        stage: "preparing",
        instructions: 0,
        functions: 0,
        blocks: 0,
        currentAddress: null,
      });
      void removeManualFunction(projectPath, normalized)
        .then((summary) => {
          setAnalysis(summary);
          setFunctionRevision((value) => value + 1);
          log(
            "info",
            `Removed the user-defined function at ${normalized}; analysis now has ${summary.functionCount} functions.`,
          );
        })
        .catch((err) => {
          log("error", `Unable to delete function: ${errorMessage(err)}`);
        })
        .finally(() => {
          setAnalysisRunning(false);
          setAnalysisProgress(null);
          setBusy(null);
        });
    },
    [projectPath, log],
  );

  const exportProjectAnnotations = useCallback(() => {
    if (!projectPath || !project) {
      log("warning", "Create or open a project to export annotations.");
      return;
    }
    void (async () => {
      try {
        const base = project.project.name.replace(/[^a-z0-9._-]+/gi, "-");
        const picked = await save({
          title: "Export annotations",
          defaultPath: `${base || "ura"}-annotations.json`,
          filters: [{ name: "JSON", extensions: ["json"] }],
        });
        if (typeof picked !== "string" || !picked) return;
        const destination = picked.toLowerCase().endsWith(".json")
          ? picked
          : `${picked}.json`;
        setBusy("Exporting annotations…");
        const summary = await exportNativeAnnotations(projectPath, destination);
        log(
          "success",
          `Exported ${summary.annotationCount} annotations, ${summary.functionNameCount} function names and ${summary.manualFunctionCount} user-defined functions to ${summary.path}.`,
        );
      } catch (err) {
        log("error", `Failed to export annotations: ${errorMessage(err)}`);
      } finally {
        setBusy(null);
      }
    })();
  }, [projectPath, project, log]);

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

  const applyLocation = useCallback(
    (resolved: HistoryEntry, nextView?: ViewKind) => {
      const sections = binary?.sections ?? [];
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
      if (inferred) focusView(inferred);
    },
    [binary, focusView],
  );

  const pushHistory = useCallback((entry: HistoryEntry) => {
    const history = historyRef.current;
    const current = history.entries[history.index];
    if (
      current &&
      current.address === entry.address &&
      current.fileOffset === entry.fileOffset
    ) {
      return;
    }
    const entries = history.entries.slice(0, history.index + 1);
    entries.push(entry);
    while (entries.length > MAX_HISTORY) entries.shift();
    historyRef.current = { entries, index: entries.length - 1 };
    setHistoryToken((value) => value + 1);
  }, []);

  useEffect(() => {
    if (!projectPath || !binary || restoringView.current) return;
    const timeout = window.setTimeout(() => {
      const history = historyRef.current;
      const state: SavedViewState = {
        version: 1,
        address: normalizeAddress(selection?.address),
        fileOffset: normalizeAddress(selection?.fileOffset),
        cfgAddress: normalizeAddress(cfgAddress),
        functionAddress: normalizeAddress(currentFunction?.address),
        history: history.entries.slice(0, history.index + 1),
        historyIndex: history.index,
        activePanel: activePanelId,
        openPanels,
      };
      saveNativeViewState(projectPath, JSON.stringify(state)).catch((err) => {
        log("warning", `Unable to store view state: ${errorMessage(err)}`);
      });
    }, 700);
    return () => window.clearTimeout(timeout);
  }, [
    projectPath,
    binary,
    selection?.address,
    selection?.fileOffset,
    cfgAddress,
    currentFunction?.address,
    activePanelId,
    openPanels,
    historyToken,
    viewRestoreToken,
    log,
  ]);

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
      applyLocation(resolved, nextView);
      pushHistory(resolved);
    },
    [binary, log, applyLocation, pushHistory],
  );

  const travelHistory = useCallback(
    (delta: number) => {
      const history = historyRef.current;
      const next = history.index + delta;
      const entry = history.entries[next];
      if (!entry) return;
      history.index = next;
      setHistoryToken((value) => value + 1);
      applyLocation(entry);
    },
    [applyLocation],
  );

  const goBack = useCallback(() => travelHistory(-1), [travelHistory]);
  const goForward = useCallback(() => travelHistory(1), [travelHistory]);
  const canGoBack = historyRef.current.index > 0;
  const canGoForward =
    historyRef.current.index >= 0 &&
    historyRef.current.index < historyRef.current.entries.length - 1;

  useEffect(() => {
    const address = selection?.address;
    if (!binary || !analysis || !address) {
      setCurrentFunction(null);
      return;
    }
    let cancelled = false;
    const timeout = window.setTimeout(() => {
      functionAt(address)
        .then((detail) => {
          if (!cancelled) setCurrentFunction(detail);
        })
        .catch(() => {
          if (!cancelled) setCurrentFunction(null);
        });
    }, 90);
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [binary, analysis, selection?.address, functionRevision]);

  const openCfg = useCallback(
    (address?: string | null) => {
      const target = normalizeAddress(address ?? selection?.address ?? null);
      if (!target) {
        log("warning", "Select an address inside a function to view its CFG.");
        return;
      }
      setCfgAddress(target);
      setSelection({
        address: target,
        fileOffset: binary
          ? addressToOffset(binary.sections, target)
          : null,
      });
      showPanel("cfg");
    },
    [binary, selection?.address, log, showPanel],
  );

  const openXrefs = useCallback(
    (address?: string | null) => {
      const target = normalizeAddress(address ?? selection?.address ?? null);
      if (!target) {
        log("warning", "Select an address to inspect its references.");
        return;
      }
      setSelection({
        address: target,
        fileOffset: binary ? addressToOffset(binary.sections, target) : null,
      });
      showPanel("xrefs");
    },
    [binary, selection?.address, log, showPanel],
  );

  const requestRename = useCallback(
    (address?: string | null) => {
      const target = normalizeAddress(
        address ?? currentFunction?.address ?? selection?.address ?? null,
      );
      if (!target) {
        log("warning", "Select a function to rename.");
        return;
      }
      if (!projectPath) {
        log("warning", "Create or open a project to rename functions.");
        return;
      }
      setRenameRequest({ address: target });
    },
    [currentFunction?.address, selection?.address, projectPath, log],
  );

  const closeRename = useCallback(() => setRenameRequest(null), []);

  const value = useMemo<SessionContextValue>(
    () => ({
      binary,
      project,
      projectPath,
      annotations,
      selection,
      navigation,
      strings,
      scanning,
      busy,
      analysis,
      analysisRunning,
      analysisProgress,
      analysisError,
      functionRevision,
      currentFunction,
      cfgAddress,
      renameRequest,
      canGoBack,
      canGoForward,
      setSelection,
      navigate,
      goBack,
      goForward,
      createUserFunction,
      deleteUserFunction,
      exportProjectAnnotations,
      openBinaryDialog,
      openBinaryPath: (path: string) => void loadBinaryPath(path),
      closeBinary,
      openProjectDialog,
      newProject,
      saveAnnotation,
      deleteAnnotation,
      scanStrings,
      startAnalysis,
      cancelAnalysis,
      renameFunction,
      openCfg,
      openXrefs,
      requestRename,
      closeRename,
      focusView,
    }),
    [
      binary,
      project,
      projectPath,
      annotations,
      selection,
      navigation,
      strings,
      scanning,
      busy,
      analysis,
      analysisRunning,
      analysisProgress,
      analysisError,
      functionRevision,
      currentFunction,
      cfgAddress,
      renameRequest,
      canGoBack,
      canGoForward,
      navigate,
      goBack,
      goForward,
      createUserFunction,
      deleteUserFunction,
      exportProjectAnnotations,
      openBinaryDialog,
      loadBinaryPath,
      closeBinary,
      openProjectDialog,
      newProject,
      saveAnnotation,
      deleteAnnotation,
      scanStrings,
      startAnalysis,
      cancelAnalysis,
      renameFunction,
      openCfg,
      openXrefs,
      requestRename,
      closeRename,
      focusView,
    ],
  );

  return (
    <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
  );
}

export function useSession(): SessionContextValue {
  const context = useContext(SessionContext);
  if (!context) throw new Error("useSession must be used inside SessionProvider");
  return context;
}
