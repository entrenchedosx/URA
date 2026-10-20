import { useEffect, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

interface VirtualListProps {
  count: number;
  estimateSize: number;
  renderRow: (index: number) => React.ReactNode;
  className?: string;
  overscan?: number;
  onEndReached?: () => void;
}

export function VirtualList({
  count,
  estimateSize,
  renderRow,
  className,
  overscan = 16,
  onEndReached,
}: VirtualListProps) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => parentRef.current,
    estimateSize: () => estimateSize,
    overscan,
  });
  const lastIndex = virtualizer.getVirtualItems().at(-1)?.index ?? -1;

  useEffect(() => {
    if (onEndReached && count > 0 && lastIndex >= count - 1) {
      onEndReached();
    }
  }, [count, lastIndex, onEndReached]);

  return (
    <div ref={parentRef} className={`overflow-auto ${className ?? ""}`}>
      <div
        className="relative w-full"
        style={{ height: `${virtualizer.getTotalSize()}px` }}
      >
        {virtualizer.getVirtualItems().map((item) => (
          <div
            key={item.key}
            className="absolute top-0 left-0 w-full"
            style={{
              height: `${item.size}px`,
              transform: `translateY(${item.start}px)`,
            }}
          >
            {renderRow(item.index)}
          </div>
        ))}
      </div>
    </div>
  );
}
