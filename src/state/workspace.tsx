import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ViewKind } from "../lib/types";
import type { WorkspacePanelId } from "../lib/panels";

export type WorkspaceIntent =
  | { kind: "focus"; panel: WorkspacePanelId; nonce: number }
  | { kind: "toggle"; panel: WorkspacePanelId; nonce: number };

interface WorkspaceContextValue {
  intent: WorkspaceIntent | null;
  resetNonce: number;
  activePanelId: WorkspacePanelId | null;
  openPanels: WorkspacePanelId[];
  focusView: (view: ViewKind) => void;
  showPanel: (panel: WorkspacePanelId) => void;
  togglePanel: (panel: WorkspacePanelId) => void;
  resetLayout: () => void;
  requestPanel: (panel: WorkspacePanelId) => void;
  togglePanelById: (panel: WorkspacePanelId) => void;
  resetLayoutRequest: () => void;
  acknowledgeIntent: (nonce: number) => void;
  setActivePanel: (panel: WorkspacePanelId | null) => void;
  setOpenPanels: (panels: WorkspacePanelId[]) => void;
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const counter = useRef(0);
  const [intent, setIntent] = useState<WorkspaceIntent | null>(null);
  const [resetNonce, setResetNonce] = useState(0);
  const [activePanelId, setActivePanel] = useState<WorkspacePanelId | null>(null);
  const [openPanels, setOpenPanels] = useState<WorkspacePanelId[]>([]);

  const requestPanel = useCallback((panel: WorkspacePanelId) => {
    counter.current += 1;
    setIntent({ kind: "focus", panel, nonce: counter.current });
  }, []);

  const togglePanelById = useCallback((panel: WorkspacePanelId) => {
    counter.current += 1;
    setIntent({ kind: "toggle", panel, nonce: counter.current });
  }, []);

  const resetLayoutRequest = useCallback(() => {
    setResetNonce((value) => value + 1);
  }, []);

  const acknowledgeIntent = useCallback((nonce: number) => {
    setIntent((current) => (current?.nonce === nonce ? null : current));
  }, []);

  const focusView = useCallback(
    (view: ViewKind) => requestPanel(view),
    [requestPanel],
  );

  const value = useMemo<WorkspaceContextValue>(
    () => ({
      intent,
      resetNonce,
      activePanelId,
      openPanels,
      focusView,
      showPanel: requestPanel,
      togglePanel: togglePanelById,
      resetLayout: resetLayoutRequest,
      requestPanel,
      togglePanelById,
      resetLayoutRequest,
      acknowledgeIntent,
      setActivePanel,
      setOpenPanels,
    }),
    [
      intent,
      resetNonce,
      activePanelId,
      openPanels,
      focusView,
      requestPanel,
      togglePanelById,
      resetLayoutRequest,
      acknowledgeIntent,
    ],
  );

  return (
    <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>
  );
}

export function useWorkspace(): WorkspaceContextValue {
  const context = useContext(WorkspaceContext);
  if (!context)
    throw new Error("useWorkspace must be used inside WorkspaceProvider");
  return context;
}
