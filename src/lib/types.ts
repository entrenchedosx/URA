export interface BinaryView {
  path: string;
  fileName: string;
  fileSize: number;
  sha256: string;
  format: string;
  architecture: string;
  bitness: number;
  endianness: string;
  imageBase: string;
  entryPoint: string | null;
  objectKind: string;
  hasSymbols: boolean;
  hasDebugSymbols: boolean;
  symbolCount: number;
  sectionCount: number;
  warnings: string[];
}

export interface SectionView {
  name: string;
  address: string;
  size: number;
  fileOffset: string | null;
  fileSize: number;
  permissions: string;
  executable: boolean;
  readable: boolean;
  writable: boolean;
  kind: string;
}

export interface SymbolView {
  name: string;
  address: string | null;
  size: number;
  kind: string;
  scope: string;
  section: string | null;
  defined: boolean;
}

export interface ImportView {
  library: string | null;
  name: string;
}

export interface ExportView {
  name: string;
  address: string;
}

export interface BinaryOpenResult {
  info: BinaryView;
  sections: SectionView[];
  symbols: SymbolView[];
  imports: ImportView[];
  exports: ExportView[];
}

export interface InstructionView {
  address: string;
  fileOffset: string | null;
  bytes: string;
  length: number;
  mnemonic: string;
  operands: string;
  text: string;
  flow: string;
  target: string | null;
  invalid: boolean;
  privileged: boolean;
}

export interface DisassemblyPage {
  startAddress: string;
  endAddress: string;
  section: string;
  architecture: string;
  instructions: InstructionView[];
  hasMore: boolean;
  warnings: string[];
}

export interface HexPage {
  offset: string;
  requestedLength: number;
  data: number[];
  eof: boolean;
  address: string | null;
  section: string | null;
  fileSize: number;
}

export interface ExtractedString {
  offset: string;
  address: string | null;
  section: string | null;
  encoding: string;
  value: string;
  length: number;
}

export interface StringScanResult {
  strings: ExtractedString[];
  truncated: boolean;
  asciiCount: number;
  utf16Count: number;
  scannedBytes: number;
}

export interface Annotation {
  id: number;
  address: string;
  label: string | null;
  note: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectInfo {
  schemaVersion: number;
  name: string;
  createdAt: string;
  updatedAt: string;
  binaryPath: string;
  binaryHash: string;
  fileSize: number;
  format: string;
  architecture: string;
  selectedAddress: string | null;
}

export interface ProjectSnapshot {
  project: ProjectInfo;
  annotations: Annotation[];
  binaryStatus: "unchanged" | "modified" | "missing" | string;
}

export type ViewKind = "disassembly" | "hex" | "strings" | "overview";

export interface Selection {
  address: string | null;
  fileOffset: string | null;
  mnemonic?: string;
  text?: string;
  bytes?: string;
}

export interface NavigationTarget {
  address?: string | null;
  fileOffset?: string | null;
  nonce: number;
}

export type NavigateFn = (
  target: { address?: string | null; fileOffset?: string | null },
  view?: ViewKind,
) => void;

export type LogLevel = "info" | "success" | "warning" | "error";

export interface LogEntry {
  id: number;
  time: string;
  level: LogLevel;
  text: string;
}
