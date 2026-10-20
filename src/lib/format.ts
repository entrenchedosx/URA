import type { SectionView } from "./types";

const HEX_PATTERN = /^[0-9a-f_]+$/i;

export function parseHex(value: string | null | undefined): bigint | null {
  if (value == null) return null;
  const trimmed = value.trim().replace(/^0x/i, "").replace(/_/g, "");
  if (!trimmed || !HEX_PATTERN.test(trimmed)) return null;
  try {
    return BigInt(`0x${trimmed}`);
  } catch {
    return null;
  }
}

export function formatHex(
  value: bigint | number | string,
  minDigits = 8,
): string {
  const numeric =
    typeof value === "bigint"
      ? value
      : typeof value === "number"
        ? BigInt(Math.max(0, Math.trunc(value)))
        : parseHex(value) ?? 0n;
  const digits = numeric.toString(16).toUpperCase();
  return `0x${digits.padStart(minDigits, "0")}`;
}

export function normalizeAddress(value: string | null | undefined): string | null {
  const parsed = parseHex(value);
  if (parsed == null) return null;
  const digits = parsed.toString(16).length;
  return formatHex(parsed, digits > 8 ? 16 : 8);
}

export function formatOffset(value: bigint | number | string): string {
  return formatHex(value, 8);
}

export function formatSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const precision = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(precision)} ${units[unit]}`;
}

export function shorten(value: string, head = 10, tail = 8): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function sectionForAddress(
  sections: SectionView[],
  address: string | bigint | null,
): SectionView | null {
  const parsed = typeof address === "bigint" ? address : parseHex(address);
  if (parsed == null) return null;
  for (const section of sections) {
    const start = parseHex(section.address);
    if (start == null) continue;
    const size = BigInt(section.size);
    if (parsed >= start && parsed < start + size) return section;
  }
  return null;
}

export function sectionForOffset(
  sections: SectionView[],
  offset: string | bigint | number | null,
): SectionView | null {
  const parsed =
    typeof offset === "bigint"
      ? offset
      : typeof offset === "number"
        ? BigInt(Math.max(0, Math.trunc(offset)))
        : parseHex(offset);
  if (parsed == null) return null;
  for (const section of sections) {
    const start = parseHex(section.fileOffset);
    if (start == null) continue;
    const size = BigInt(section.fileSize);
    if (parsed >= start && parsed < start + size) return section;
  }
  return null;
}

export function addressToOffset(
  sections: SectionView[],
  address: string | bigint | null,
): string | null {
  const parsed = typeof address === "bigint" ? address : parseHex(address);
  if (parsed == null) return null;
  const section = sectionForAddress(sections, parsed);
  if (!section) return null;
  const sectionStart = parseHex(section.address);
  const fileStart = parseHex(section.fileOffset);
  if (sectionStart == null || fileStart == null) return null;
  const delta = parsed - sectionStart;
  if (delta < 0n || delta >= BigInt(section.fileSize)) return null;
  return formatHex(fileStart + delta);
}

export function offsetToAddress(
  sections: SectionView[],
  offset: string | bigint | number | null,
): string | null {
  const parsed =
    typeof offset === "bigint"
      ? offset
      : typeof offset === "number"
        ? BigInt(Math.max(0, Math.trunc(offset)))
        : parseHex(offset);
  if (parsed == null) return null;
  const section = sectionForOffset(sections, parsed);
  if (!section) return null;
  const fileStart = parseHex(section.fileOffset);
  const addressStart = parseHex(section.address);
  if (fileStart == null || addressStart == null) return null;
  return formatHex(addressStart + (parsed - fileStart));
}

export function resolveNavigation(
  sections: SectionView[],
  address: string | null | undefined,
  fileOffset: string | null | undefined,
): { address: string | null; fileOffset: string | null } {
  const resolvedAddress =
    normalizeAddress(address) ??
    (fileOffset != null ? offsetToAddress(sections, fileOffset) : null);
  const resolvedOffset =
    normalizeAddress(fileOffset) ??
    (resolvedAddress != null ? addressToOffset(sections, resolvedAddress) : null);
  return { address: resolvedAddress, fileOffset: resolvedOffset };
}

export function parseNumberInput(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}
