import { invoke } from "@tauri-apps/api/core";
import type {
  Annotation,
  BinaryOpenResult,
  DisassemblyPage,
  HexPage,
  ProjectInfo,
  ProjectSnapshot,
  StringScanResult,
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
