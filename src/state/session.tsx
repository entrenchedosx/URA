import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  closeBinary as closeNativeBinary,
  createAnalysisProject,
  deleteAnnotation as deleteNativeAnnotation,
  errorMessage,
  extractStrings,
  openAnalysisProject,
  openBinary as openNativeBinary,
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
  Annotation,
  BinaryOpenResult,
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

  const lastSavedAddress = useRef<string | null>(null);
  const projectRef = useRef<ProjectSnapshot | null>(null);
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
    void closeNativeBinary();
    setBinary(null);
    setSelection(null);
    setStrings(null);
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
        log(
          "success",
          `Opened project “${snapshot.project.name}” (${snapshot.annotations.length} annotations).`,
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
      navigate,
      openBinaryDialog,
      loadBinaryPath,
      closeBinary,
      openProjectDialog,
      newProject,
      saveAnnotation,
      deleteAnnotation,
      scanStrings,
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
