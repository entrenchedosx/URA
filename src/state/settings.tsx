import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

export type Density = "compact" | "comfortable" | "spacious";

export interface AppSettings {
  codeFontSize: number;
  density: Density;
  showBytes: boolean;
}

export const DEFAULT_SETTINGS: AppSettings = {
  codeFontSize: 12,
  density: "comfortable",
  showBytes: true,
};

const STORAGE_KEY = "ura:settings:v1";

export const CODE_FONT_MIN = 10;
export const CODE_FONT_MAX = 17;

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function normalizeSettings(value: Partial<AppSettings> | null): AppSettings {
  const density: Density =
    value?.density === "compact" ||
    value?.density === "comfortable" ||
    value?.density === "spacious"
      ? value.density
      : DEFAULT_SETTINGS.density;
  return {
    codeFontSize: clamp(
      typeof value?.codeFontSize === "number" && Number.isFinite(value.codeFontSize)
        ? Math.round(value.codeFontSize)
        : DEFAULT_SETTINGS.codeFontSize,
      CODE_FONT_MIN,
      CODE_FONT_MAX,
    ),
    density,
    showBytes:
      typeof value?.showBytes === "boolean"
        ? value.showBytes
        : DEFAULT_SETTINGS.showBytes,
  };
}

export function loadSettings(): AppSettings {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_SETTINGS;
    return normalizeSettings(JSON.parse(raw) as Partial<AppSettings>);
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export function saveSettings(settings: AppSettings): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // Preferences are best-effort; a full localStorage must not break the app.
  }
}

interface SettingsContextValue {
  settings: AppSettings;
  update: (patch: Partial<AppSettings>) => void;
  reset: () => void;
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

function applySettings(settings: AppSettings): void {
  const root = document.documentElement;
  root.style.setProperty("--ura-code-size", `${settings.codeFontSize}px`);
  root.dataset.density = settings.density;
}

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const [settings, setSettings] = useState<AppSettings>(() => loadSettings());

  useEffect(() => {
    applySettings(settings);
    saveSettings(settings);
  }, [settings]);

  const update = useCallback((patch: Partial<AppSettings>) => {
    setSettings((previous) => normalizeSettings({ ...previous, ...patch }));
  }, []);

  const reset = useCallback(() => setSettings(DEFAULT_SETTINGS), []);

  const value = useMemo(
    () => ({ settings, update, reset }),
    [settings, update, reset],
  );

  return (
    <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
  );
}

export function useSettings(): SettingsContextValue {
  const context = useContext(SettingsContext);
  if (!context) throw new Error("useSettings must be used inside SettingsProvider");
  return context;
}

export function rowHeightFor(settings: AppSettings): number {
  const base =
    settings.density === "compact"
      ? 21
      : settings.density === "spacious"
        ? 26
        : 23;
  return Math.max(base, settings.codeFontSize + 9);
}
