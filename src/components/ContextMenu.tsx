import { useEffect, useLayoutEffect, useRef, useState } from "react";

export interface ContextMenuItem {
  label: string;
  icon?: React.ComponentType<{ className?: string }>;
  shortcut?: string;
  danger?: boolean;
  disabled?: boolean;
  onSelect: () => void;
}

interface ContextMenuProps {
  x: number;
  y: number;
  items: ContextMenuItem[];
  onClose: () => void;
}

export function ContextMenu({ x, y, items, onClose }: ContextMenuProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState({ left: x, top: y });

  useLayoutEffect(() => {
    const element = ref.current;
    if (!element) return;
    const rect = element.getBoundingClientRect();
    const left = Math.min(x, window.innerWidth - rect.width - 8);
    const top = Math.min(y, window.innerHeight - rect.height - 8);
    setPosition({ left: Math.max(8, left), top: Math.max(8, top) });
  }, [x, y]);

  useEffect(() => {
    const close = () => onClose();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("resize", close);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("resize", close);
      window.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  return (
    <div
      ref={ref}
      className="fixed z-50 min-w-48 rounded-md border border-edge-strong bg-obsidian-800 p-1 shadow-[0_16px_48px_rgba(0,0,0,0.6)]"
      style={{ left: position.left, top: position.top }}
      onMouseDown={(event) => event.stopPropagation()}
      onContextMenu={(event) => event.preventDefault()}
      role="menu"
    >
      {items.map((item, index) =>
        item.label === "-" ? (
          <div key={`separator-${index}`} className="my-1 h-px bg-edge" />
        ) : (
          <button
            key={item.label}
            className={`flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-[11.5px] transition-colors hover:bg-obsidian-700 disabled:pointer-events-none disabled:opacity-40 ${
              item.danger ? "text-red-300" : "text-ink-200"
            }`}
            disabled={item.disabled}
            role="menuitem"
            onClick={() => {
              item.onSelect();
              onClose();
            }}
          >
            {item.icon && <item.icon className="size-3.5 shrink-0 text-ink-500" />}
            <span className="flex-1">{item.label}</span>
            {item.shortcut && (
              <span className="font-mono text-[9.5px] text-ink-500">
                {item.shortcut}
              </span>
            )}
          </button>
        ),
      )}
    </div>
  );
}
