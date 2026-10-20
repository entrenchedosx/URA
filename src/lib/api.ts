import { invoke } from "@tauri-apps/api/core";
import type {
  AnalysisStateView,
  AnalysisSummary,
  Annotation,
  BinaryOpenResult,
  DisassemblyPage,
  FunctionCfg,
  FunctionDetail,
  FunctionListPage,
  ExportSummary,
  FunctionQuery,
  HexPage,
  ProjectInfo,
  ProjectSnapshot,
  RenameResult,
  StringScanResult,
  XrefPage,
} from "./types";

export function errorMessage(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  if (error && typeof error === "object" && "message" in error) {
    return String((error as { message: unknown }).message);
  }
  return String(error);
}

export async function openBinary(path: string): Promise<BinaryOpenResult> {
  return invoke<BinaryOpenResult>("open_binary", { path });
}

export async function closeBinary(): Promise<void> {
  return invoke("close_binary");
}

export async function takeStartupPath(): Promise<string | null> {
  return invoke<string | null>("take_startup_path");
}

export async function disassemble(
  address: string,
  count: number,
): Promise<DisassemblyPage> {
  return invoke<DisassemblyPage>("disassemble", { address, count });
}

export async function readHex(
  offset: number,
  length: number,
): Promise<HexPage> {
  return invoke<HexPage>("read_hex", { offset, length });
}

export async function extractStrings(
  minLength: number,
  includeAscii: boolean,
  includeUtf16: boolean,
): Promise<StringScanResult> {
  return invoke<StringScanResult>("extract_strings", {
    minLength,
    includeAscii,
    includeUtf16,
  });
}

export async function createAnalysisProject(
  projectPath: string,
  name: string,
): Promise<ProjectInfo> {
  return invoke<ProjectInfo>("create_analysis_project", { projectPath, name });
}

export async function openAnalysisProject(
  projectPath: string,
): Promise<ProjectSnapshot> {
  return invoke<ProjectSnapshot>("open_analysis_project", { projectPath });
}

export async function saveAnnotation(
  projectPath: string,
  address: string,
  label: string | null,
  note: string,
): Promise<Annotation> {
  return invoke<Annotation>("save_annotation", {
    projectPath,
    address,
    label,
    note,
  });
}

export async function setProjectAddress(
  projectPath: string,
  address: string,
): Promise<string> {
  return invoke<string>("set_project_address", { projectPath, address });
}

export async function deleteAnnotation(
  projectPath: string,
  annotationId: number,
): Promise<void> {
  return invoke("delete_annotation", { projectPath, annotationId });
}

export async function analyzeBinary(
  projectPath?: string | null,
): Promise<AnalysisSummary> {
  return invoke<AnalysisSummary>("analyze_binary", {
    options: null,
    projectPath: projectPath ?? null,
  });
}

export async function createManualFunction(
  projectPath: string,
  address: string,
): Promise<AnalysisSummary> {
  return invoke<AnalysisSummary>("create_manual_function", {
    projectPath,
    address,
  });
}

export async function removeManualFunction(
  projectPath: string,
  address: string,
): Promise<AnalysisSummary> {
  return invoke<AnalysisSummary>("remove_manual_function", {
    projectPath,
    address,
  });
}

export async function saveViewState(
  projectPath: string,
  state: string,
): Promise<void> {
  return invoke("save_view_state", { projectPath, state });
}

export async function loadViewState(
  projectPath: string,
): Promise<string | null> {
  return invoke<string | null>("load_view_state", { projectPath });
}

export async function exportAnnotations(
  projectPath: string,
  destination: string,
): Promise<ExportSummary> {
  return invoke<ExportSummary>("export_annotations", {
    projectPath,
    destination,
  });
}

export async function cancelAnalysis(): Promise<boolean> {
  return invoke<boolean>("cancel_analysis");
}

export async function analysisState(): Promise<AnalysisStateView> {
  return invoke<AnalysisStateView>("analysis_state");
}

export async function listFunctions(
  query: FunctionQuery,
): Promise<FunctionListPage> {
  return invoke<FunctionListPage>("list_functions", { query });
}

export async function functionAt(
  address: string,
): Promise<FunctionDetail | null> {
  return invoke<FunctionDetail | null>("function_at", { address });
}

export async function functionCfg(
  address: string,
  maxBlocks?: number,
): Promise<FunctionCfg> {
  return invoke<FunctionCfg>("function_cfg", { address, maxBlocks });
}

export async function xrefsTo(
  address: string,
  limit?: number,
): Promise<XrefPage> {
  return invoke<XrefPage>("xrefs_to", { address, limit });
}

export async function xrefsFrom(
  address: string,
  limit?: number,
): Promise<XrefPage> {
  return invoke<XrefPage>("xrefs_from", { address, limit });
}

export async function renameFunction(
  projectPath: string,
  address: string,
  name: string,
): Promise<RenameResult> {
  return invoke<RenameResult>("rename_function", {
    projectPath,
    address,
    name,
  });
}
