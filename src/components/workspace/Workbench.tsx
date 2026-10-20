import { useCallback, useEffect, useRef, useState } from "react";
import {
  DockviewReact,
  type DockviewReadyEvent,
  type IDockviewPanelProps,
} from "dockview-react";
import type { DockviewApi, DockviewTheme } from "dockview";
import { DisassemblyView } from "../DisassemblyView";
import { Explorer } from "../Explorer";
import { HexView } from "../HexView";
import { Inspector } from "../Inspector";
import { MessagesPanel } from "../MessagesPanel";
import { Overview } from "../Overview";
import { StringsView } from "../StringsView";
import {
  WORKSPACE_PANEL_TITLES,
  type WorkspacePanelId,
} from "../../lib/panels";
import { useWorkspace } from "../../state/workspace";

const STORAGE_KEY = "ura:workspace:v1";
const LAYOUT_VERSION = 1;

interface StoredLayout {
  version: number;
  layout: unknown;
}

const panelComponents: Record<string, React.FunctionComponent<IDockviewPanelProps>> = {
  explorer: () => <Explorer />,
  disassembly: () => <DisassemblyView />,
  hex: () => <HexView />,
  strings: () => <StringsView />,
  overview: () => <Overview />,
  inspector: () => <Inspector />,
  messages: () => <MessagesPanel />,
};

const uraTheme: DockviewTheme = {
  name: "ura",
  className: "dockview-theme-ura",
  colorScheme: "dark",
  gap: 0,
};

function componentFor(panel: WorkspacePanelId): string {
  return panel;
}

function readStoredLayout(): StoredLayout | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as StoredLayout;
    if (parsed?.version !== LAYOUT_VERSION || !parsed.layout) return null;
    const panels = (parsed.layout as { panels?: Record<string, unknown> }).panels;
    if (!panels || typeof panels !== "object") return null;
    const ids = Object.keys(panels);
    if (ids.length === 0) return null;
    for (const id of ids) {
      if (!(id in WORKSPACE_PANEL_TITLES)) return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function writeStoredLayout(layout: unknown): void {
  try {
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ version: LAYOUT_VERSION, layout } satisfies StoredLayout),
    );
  } catch {
    // Layout persistence is best-effort.
  }
}

function buildDefaultLayout(api: DockviewApi): void {
  api.clear();
  api.addPanel({
    id: "messages",
    component: componentFor("messages"),
    title: WORKSPACE_PANEL_TITLES.messages,
    minimumHeight: 80,
  });
  api.addPanel({
    id: "disassembly",
    component: componentFor("disassembly"),
    title: WORKSPACE_PANEL_TITLES.disassembly,
    position: { referencePanel: "messages", direction: "above" },
    minimumWidth: 320,
  });
  api.addPanel({
    id: "overview",
    component: componentFor("overview"),
    title: WORKSPACE_PANEL_TITLES.overview,
    position: { referencePanel: "disassembly", direction: "within" },
    inactive: true,
  });
  api.addPanel({
    id: "strings",
    component: componentFor("strings"),
    title: WORKSPACE_PANEL_TITLES.strings,
    position: { referencePanel: "disassembly", direction: "within" },
    inactive: true,
  });
  api.addPanel({
    id: "explorer",
    component: componentFor("explorer"),
    title: WORKSPACE_PANEL_TITLES.explorer,
    position: { referencePanel: "disassembly", direction: "left" },
    initialWidth: 258,
    minimumWidth: 180,
  });
  api.addPanel({
    id: "inspector",
    component: componentFor("inspector"),
    title: WORKSPACE_PANEL_TITLES.inspector,
    position: { referencePanel: "disassembly", direction: "right" },
    initialWidth: 300,
    minimumWidth: 220,
  });
  api.addPanel({
    id: "hex",
    component: componentFor("hex"),
    title: WORKSPACE_PANEL_TITLES.hex,
    position: { referencePanel: "disassembly", direction: "below" },
    initialHeight: 280,
    minimumHeight: 100,
  });

  api.getPanel("messages")?.group.api.setSize({ height: 148 });
  api.getPanel("explorer")?.group.api.setSize({ width: 258 });
  api.getPanel("inspector")?.group.api.setSize({ width: 300 });
  api.getPanel("hex")?.group.api.setSize({ height: 280 });
  api.getPanel("disassembly")?.api.setActive();
}

function syncPanels(api: DockviewApi): WorkspacePanelId[] {
  return api.panels
    .map((panel) => panel.id)
    .filter((id): id is WorkspacePanelId => id in WORKSPACE_PANEL_TITLES);
}

export function Workbench() {
  const {
    intent,
    resetNonce,
    acknowledgeIntent,
    setActivePanel,
    setOpenPanels,
  } = useWorkspace();
  const apiRef = useRef<DockviewApi | null>(null);
  const disposables = useRef<Array<{ dispose: () => void }>>([]);
  const saveTimer = useRef<number | null>(null);
  const [ready, setReady] = useState(false);
  const lastReset = useRef(resetNonce);

  const persistSoon = useCallback(() => {
    if (saveTimer.current != null) window.clearTimeout(saveTimer.current);
    saveTimer.current = window.setTimeout(() => {
      saveTimer.current = null;
      const api = apiRef.current;
      if (!api) return;
      writeStoredLayout(api.toJSON());
    }, 350);
  }, []);

  const handleReady = useCallback(
    (event: DockviewReadyEvent) => {
      const api = event.api;
      apiRef.current = api;
      for (const disposable of disposables.current) disposable.dispose();
      disposables.current = [];

      const stored = readStoredLayout();
      let restored = false;
      if (stored) {
        try {
          api.fromJSON(stored.layout as never);
          restored = api.panels.length > 0;
        } catch {
          restored = false;
        }
      }
      if (!restored) buildDefaultLayout(api);

      setOpenPanels(syncPanels(api));
      const active = api.activePanel;
      setActivePanel(
        active && active.id in WORKSPACE_PANEL_TITLES
          ? (active.id as WorkspacePanelId)
          : null,
      );

      disposables.current.push(
        api.onDidLayoutChange(() => {
          setOpenPanels(syncPanels(api));
          persistSoon();
        }),
        api.onDidActivePanelChange((panelEvent) => {
          const panel = panelEvent.panel;
          setActivePanel(
            panel && panel.id in WORKSPACE_PANEL_TITLES
              ? (panel.id as WorkspacePanelId)
              : null,
          );
          persistSoon();
        }),
      );

      setReady(true);
    },
    [persistSoon, setActivePanel, setOpenPanels],
  );

  useEffect(() => {
    return () => {
      for (const disposable of disposables.current) disposable.dispose();
      disposables.current = [];
      if (saveTimer.current != null) window.clearTimeout(saveTimer.current);
    };
  }, []);

  const ensurePanel = useCallback(
    (api: DockviewApi, panel: WorkspacePanelId) => {
      const existing = api.getPanel(panel);
      if (existing) {
        existing.api.setActive();
        return;
      }
      const anchor =
        api.getPanel("disassembly") ??
        api.activePanel ??
        api.panels[0] ??
        null;
      const isView =
        panel === "disassembly" ||
        panel === "hex" ||
        panel === "strings" ||
        panel === "overview";
      let position:
        | { referencePanel: string; direction: "within" | "left" | "right" | "below" | "above" }
        | undefined;
      if (anchor) {
        if (panel === "explorer") {
          position = { referencePanel: anchor.id, direction: "left" };
        } else if (panel === "inspector") {
          position = { referencePanel: anchor.id, direction: "right" };
        } else if (panel === "messages") {
          position = { referencePanel: anchor.id, direction: "below" };
        } else {
          position = { referencePanel: anchor.id, direction: "within" };
        }
      }
      api.addPanel({
        id: panel,
        component: componentFor(panel),
        title: WORKSPACE_PANEL_TITLES[panel],
        position,
        initialWidth:
          panel === "explorer" ? 258 : panel === "inspector" ? 300 : undefined,
        initialHeight: panel === "messages" ? 148 : isView ? undefined : undefined,
        minimumWidth: panel === "explorer" ? 180 : panel === "inspector" ? 220 : undefined,
      });
      api.getPanel(panel)?.api.setActive();
    },
    [],
  );

  useEffect(() => {
    if (!ready || !intent) return;
    const api = apiRef.current;
    if (!api) return;
    if (intent.kind === "focus") {
      ensurePanel(api, intent.panel);
    } else {
      const existing = api.getPanel(intent.panel);
      if (existing) {
        api.removePanel(existing);
      } else {
        ensurePanel(api, intent.panel);
      }
    }
    setOpenPanels(syncPanels(api));
    acknowledgeIntent(intent.nonce);
  }, [ready, intent, ensurePanel, acknowledgeIntent, setOpenPanels]);

  useEffect(() => {
    if (!ready) return;
    if (resetNonce === lastReset.current) return;
    lastReset.current = resetNonce;
    const api = apiRef.current;
    if (!api) return;
    try {
      window.localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
    buildDefaultLayout(api);
    setOpenPanels(syncPanels(api));
    setActivePanel("disassembly");
    writeStoredLayout(api.toJSON());
  }, [resetNonce, ready, setActivePanel, setOpenPanels]);

  return (
    <DockviewReact
      className="h-full w-full"
      theme={uraTheme}
      components={panelComponents}
      onReady={handleReady}
      defaultRenderer="always"
      disableFloatingGroups={false}
      floatingGroupBounds="boundedWithinViewport"
    />
  );
}
