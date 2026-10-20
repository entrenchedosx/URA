import { useCallback, useEffect, useState } from "react";
import { AlertCircle, X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { AboutDialog } from "./components/AboutDialog";
import { CommandPalette } from "./components/CommandPalette";
import { GoToDialog } from "./components/GoToDialog";
import { RenameFunctionDialog } from "./components/RenameFunctionDialog";
import { SettingsDialog } from "./components/SettingsDialog";
import { StatusBar } from "./components/StatusBar";
import { Toolbar } from "./components/Toolbar";
import { Welcome } from "./components/Welcome";
import { Workbench } from "./components/workspace/Workbench";
import { MessagesProvider, useMessages } from "./state/messages";
import { SessionProvider, useSession } from "./state/session";
import { SettingsProvider } from "./state/settings";
import { WorkspaceProvider, useWorkspace } from "./state/workspace";

function Shell() {
  const {
    binary,
    project,
    openBinaryDialog,
    openProjectDialog,
    newProject,
    requestRename,
    goBack,
    goForward,
  } = useSession();
  const { focusView } = useWorkspace();
  const { toast, dismissToast } = useMessages();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [goToOpen, setGoToOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);

  const openPalette = useCallback(() => {
    setGoToOpen(false);
    setSettingsOpen(false);
    setPaletteOpen(true);
  }, []);

  const openGoTo = useCallback(() => {
    setPaletteOpen(false);
    setSettingsOpen(false);
    setGoToOpen(true);
  }, []);

  const openSettings = useCallback(() => {
    setPaletteOpen(false);
    setSettingsOpen(true);
  }, []);

  useEffect(() => {
    const title = binary
      ? project
        ? `${binary.info.fileName} — ${project.project.name} — URA`
        : `${binary.info.fileName} — URA`
      : "URA";
    void getCurrentWindow()
      .setTitle(title)
      .catch(() => undefined);
  }, [binary, project]);

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
        openPalette();
        return;
      }
      if (mod && event.key === ",") {
        event.preventDefault();
        openSettings();
        return;
      }
      if (mod && !event.shiftKey && event.key.toLowerCase() === "g") {
        event.preventDefault();
        openGoTo();
        return;
      }
      if (event.altKey && event.key === "ArrowLeft") {
        event.preventDefault();
        goBack();
        return;
      }
      if (event.altKey && event.key === "ArrowRight") {
        event.preventDefault();
        goForward();
        return;
      }
      if (mod && !event.shiftKey && event.key.toLowerCase() === "o") {
        event.preventDefault();
        openBinaryDialog();
        return;
      }
      if (mod && event.shiftKey && event.key.toLowerCase() === "o") {
        event.preventDefault();
        openProjectDialog();
        return;
      }
      if (mod && event.key.toLowerCase() === "n") {
        event.preventDefault();
        newProject();
        return;
      }
      if (mod && ["1", "2", "3", "4"].includes(event.key)) {
        event.preventDefault();
        if (binary) {
          const view = (
            ["disassembly", "hex", "strings", "overview"] as const
          )[Number(event.key) - 1];
          focusView(view);
        }
        return;
      }
      if (event.key === "F2") {
        event.preventDefault();
        requestRename();
        return;
      }
      if (!typing && event.key === "Escape") {
        setPaletteOpen(false);
        setGoToOpen(false);
        setSettingsOpen(false);
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [
    binary,
    focusView,
    goBack,
    goForward,
    newProject,
    openBinaryDialog,
    openGoTo,
    openPalette,
    openProjectDialog,
    openSettings,
    requestRename,
  ]);

  return (
    <div className="flex h-full flex-col overflow-hidden bg-obsidian-950">
      <Toolbar
        onOpenPalette={openPalette}
        onOpenGoTo={openGoTo}
        onOpenSettings={openSettings}
      />

      <main className="relative min-h-0 flex-1">
        <Workbench />
        {!binary && <Welcome />}
      </main>

      <StatusBar />

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onOpenSettings={openSettings}
        onOpenGoTo={openGoTo}
      />
      <GoToDialog open={goToOpen} onClose={() => setGoToOpen(false)} />
      <SettingsDialog
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        onOpenAbout={() => setAboutOpen(true)}
      />
      <AboutDialog open={aboutOpen} onClose={() => setAboutOpen(false)} />
      <RenameFunctionDialog />

      {toast && (
        <div className="fixed bottom-11 right-4 z-[60] flex max-w-md items-start gap-2 rounded-lg border border-red-500/35 bg-obsidian-800 px-3 py-2 shadow-2xl">
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
            onClick={dismissToast}
            aria-label="Dismiss error"
          >
            <X className="size-3" />
          </button>
        </div>
      )}
    </div>
  );
}

export default function App() {
  return (
    <SettingsProvider>
      <MessagesProvider>
        <WorkspaceProvider>
          <SessionProvider>
            <Shell />
          </SessionProvider>
        </WorkspaceProvider>
      </MessagesProvider>
    </SettingsProvider>
  );
}
