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
  deleteAnnotation as deleteNativeAnnotation,
  errorMessage,
  extractStrings,
  functionAt,
  openAnalysisProject,
  openBinary as openNativeBinary,
  renameFunction as renameNativeFunction,
  saveAnnotation as saveNativeAnnotation,
  setProjectAddress,
  takeStartupPath,
} from "../lib/api";
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
  setSelection: (selection: Selection | null) => void;
  navigate: NavigateFn;
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

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const { log } = useMessages();
  const { focusView: workspaceFocusView, showPanel } = useWorkspace();

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
        setBusy("Opening project…");
        const snapshot = await openAnalysisProject(picked);
        setProject(snapshot);
        setProjectPath(picked);
        projectRef.current = snapshot;
        setFunctionRevision((value) => value + 1);
        log(
          "success",
          `Opened project “${snapshot.project.name}” (${snapshot.annotations.length} annotations, ${snapshot.functionNames.length} custom function names).`,
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
          return;
        }

        setBusy("Loading project binary…");
        const result = await openNativeBinary(snapshot.project.binaryPath);
        applyBinary(result, snapshot.project.selectedAddress);
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
        log("error", `Failed to open project: ${errorMessage(err)}`);
      } finally {
        setBusy(null);
      }
    })();
  }, [applyBinary, log]);

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
          binaryStatus: "unchanged",
        };
        setProject(snapshot);
        setProjectPath(projectFile);
        projectRef.current = snapshot;
        lastSavedAddress.current = null;
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
      void analyzeBinary()
        .then((summary) => {
          if (analysisRunId.current !== runId) return;
          setAnalysis(summary);
          setFunctionRevision((value) => value + 1);
          const counts = `${summary.functionCount} functions, ${summary.blockCount} blocks, ${summary.xrefCount} xrefs from ${summary.instructionCount} instructions`;
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
  }, [binary, log]);

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
      if (inferred) focusView(inferred);
    },
    [binary, log, focusView],
  );

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
      setSelection,
      navigate,
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
      navigate,
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
