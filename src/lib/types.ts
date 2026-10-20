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
  targetName: string | null;
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

export interface FunctionNameEntry {
  address: string;
  name: string;
  updatedAt: string;
}

export interface ProjectSnapshot {
  project: ProjectInfo;
  annotations: Annotation[];
  functionNames: FunctionNameEntry[];
  binaryStatus: "unchanged" | "modified" | "missing" | string;
}

export interface AnalysisDiagnostic {
  address: string | null;
  message: string;
}

export interface AnalysisSummary {
  instructionCount: number;
  functionCount: number;
  blockCount: number;
  xrefCount: number;
  cancelled: boolean;
  truncated: boolean;
  diagnosticsDropped: number;
  elapsedMs: number;
  diagnostics: AnalysisDiagnostic[];
}

export interface AnalysisProgress {
  stage: "preparing" | "discovering" | "finalizing" | "complete";
  instructions: number;
  functions: number;
  blocks: number;
  currentAddress: string | null;
}

export interface AnalysisStateView {
  summary: AnalysisSummary | null;
  running: boolean;
}

export type FunctionSort =
  | "address"
  | "name"
  | "instructions"
  | "blocks"
  | "references";

export interface FunctionSummary {
  address: string;
  name: string;
  symbol: string | null;
  customName: string | null;
  origin: string;
  verified: boolean;
  endAddress: string;
  size: number;
  instructionCount: number;
  blockCount: number;
  referenceCount: number;
  callerCount: number;
  calleeCount: number;
}

export interface FunctionRef {
  address: string;
  name: string;
  customName: string | null;
}

export interface FunctionDetail extends FunctionSummary {
  callers: FunctionRef[];
  callees: FunctionRef[];
}

export interface FunctionListPage {
  total: number;
  offset: number;
  limit: number;
  functions: FunctionSummary[];
}

export interface FunctionQuery {
  search?: string;
  sort?: FunctionSort;
  descending?: boolean;
  offset?: number;
  limit?: number;
}

export interface CfgLine {
  address: string;
  text: string;
  targetName: string | null;
}

export interface CfgEdge {
  target: string;
  kind: "fallthrough" | "jump" | "taken" | string;
}

export interface CfgBlock {
  address: string;
  endAddress: string;
  instructionCount: number;
  omittedInstructions: number;
  lines: CfgLine[];
  edges: CfgEdge[];
}

export interface FunctionCfg {
  function: FunctionSummary;
  totalBlocks: number;
  instructionCount: number;
  truncated: boolean;
  blocks: CfgBlock[];
}

export interface XrefView {
  from: string;
  to: string;
  kind: "call" | "jump" | "conditionalJump" | string;
  sourceFunction: FunctionRef | null;
  targetFunction: FunctionRef | null;
}

export interface XrefPage {
  total: number;
  references: XrefView[];
}

export interface RenameResult {
  address: string;
  name: string | null;
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
