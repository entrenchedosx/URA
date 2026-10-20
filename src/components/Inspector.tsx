import { useEffect, useMemo, useState } from "react";
import {
  BookMarked,
  Check,
  Clipboard,
  Database,
  FilePlus2,
  GitFork,
  Info,
  MapPin,
  Pencil,
  Save,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
} from "lucide-react";
import { errorMessage, xrefsFrom, xrefsTo } from "../lib/api";
import type { Annotation, XrefView } from "../lib/types";
import {
  addressToOffset,
  formatHex,
  formatSize,
  normalizeAddress,
  sectionForAddress,
  sectionForOffset,
  shorten,
} from "../lib/format";
import { useMessages } from "../state/messages";
import { useSession } from "../state/session";

function CopyButton({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="icon-btn size-5 shrink-0"
      title={`Copy ${label ?? value}`}
      aria-label={`Copy ${label ?? value}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? (
        <Check className="size-3 text-emerald-400" />
      ) : (
        <Clipboard className="size-3" />
      )}
    </button>
  );
}

function Field({
  label,
  children,
  copy,
}: {
  label: string;
  children: React.ReactNode;
  copy?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="shrink-0 text-ink-500">{label}</span>
      <span className="flex min-w-0 items-center gap-0.5 font-mono text-ink-300">
        <span className="truncate">{children}</span>
        {copy && <CopyButton value={copy} label={label} />}
      </span>
    </div>
  );
}

function AnnotationSummary({
  annotation,
  active,
  onSelect,
  onDelete,
  canDelete,
}: {
  annotation: Annotation;
  active: boolean;
  onSelect: () => void;
  onDelete: () => void;
  canDelete: boolean;
}) {
  return (
    <div
      className={`group flex items-start gap-1.5 rounded border px-1.5 py-1 transition-colors ${
        active
          ? "border-accent-500/30 bg-accent-500/5"
          : "border-transparent hover:border-edge hover:bg-obsidian-800"
      }`}
    >
      <button
        className="min-w-0 flex-1 text-left"
        onClick={onSelect}
        title={annotation.note || annotation.address}
      >
        <div className="flex items-center gap-1.5">
          <span className="font-mono text-[10px] text-accent-400/90">
            {formatHex(annotation.address)}
          </span>
          {annotation.label && (
            <span className="truncate text-[10.5px] font-medium text-ink-300">
              {annotation.label}
            </span>
          )}
        </div>
        {annotation.note && (
          <div className="mt-0.5 line-clamp-2 text-[10px] leading-snug text-ink-500">
            {annotation.note}
          </div>
        )}
      </button>
      <button
        className="icon-btn size-5 shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
        title="Delete annotation"
        onClick={onDelete}
        disabled={!canDelete}
      >
        <Trash2 className="size-3 text-red-400/80" />
      </button>
    </div>
  );
}

export function Inspector() {
  const {
    binary,
    project,
    projectPath,
    annotations,
    selection,
    busy,
    navigate,
    saveAnnotation,
    deleteAnnotation,
    newProject,
    analysis,
    functionRevision,
    currentFunction,
    openCfg,
    openXrefs,
    requestRename,
  } = useSession();
  const { log } = useMessages();
  const [label, setLabel] = useState("");
  const [note, setNote] = useState("");
  const [references, setReferences] = useState<{
    incoming: XrefView[];
    outgoing: XrefView[];
    incomingTotal: number;
    outgoingTotal: number;
  } | null>(null);

  const address = normalizeAddress(selection?.address);
  const fileOffset =
    normalizeAddress(selection?.fileOffset) ??
    (address && binary ? addressToOffset(binary.sections, address) : null);

  const section = useMemo(() => {
    if (!binary) return null;
    return (
      sectionForAddress(binary.sections, address) ??
      sectionForOffset(binary.sections, fileOffset)
    );
  }, [binary, address, fileOffset]);

  const existing = useMemo(() => {
    if (!address) return null;
    return (
      annotations.find(
        (annotation) => normalizeAddress(annotation.address) === address,
      ) ?? null
    );
  }, [annotations, address]);

  useEffect(() => {
    setLabel(existing?.label ?? "");
    setNote(existing?.note ?? "");
  }, [address, existing?.id, existing?.label, existing?.note]);

  useEffect(() => {
    if (!analysis || !address) {
      setReferences(null);
      return;
    }
    let cancelled = false;
    setReferences(null);
    const timeout = window.setTimeout(() => {
      Promise.all([xrefsTo(address, 4), xrefsFrom(address, 4)])
        .then(([incoming, outgoing]) => {
          if (cancelled) return;
          setReferences({
            incoming: incoming.references,
            outgoing: outgoing.references,
            incomingTotal: incoming.total,
            outgoingTotal: outgoing.total,
          });
        })
        .catch((err) => {
          if (cancelled) return;
          setReferences(null);
          log(
            "warning",
            `Unable to load references: ${errorMessage(err)}`,
          );
        });
    }, 140);
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [analysis, address, functionRevision, log]);

  const dirty =
    existing == null
      ? label.trim().length > 0 || note.trim().length > 0
      : label.trim() !== (existing.label ?? "") || note.trim() !== existing.note;

  const submit = () => {
    if (!address) return;
    saveAnnotation(address, label, note);
  };

  const projectInfo = project?.project ?? null;
  const binaryStatus = project?.binaryStatus ?? null;

  return (
    <div className="flex h-full min-h-0 w-full flex-col bg-obsidian-850">
      <div className="flex h-7 shrink-0 items-center justify-between border-b border-edge px-2.5">
        <span className="flex items-center gap-1.5 text-[9.5px] font-semibold uppercase tracking-[0.16em] text-ink-500">
          <Info className="size-3" />
          Selection
        </span>
        <span className="truncate font-mono text-[9.5px] text-ink-500">
          {section?.name ?? (selection ? "unmapped" : "nothing selected")}
        </span>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        <section className="border-b border-edge p-2.5">
          {selection ? (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="break-all font-mono text-[13.5px] font-medium text-accent-300">
                  {address ?? "no address"}
                </span>
                {address && <CopyButton value={address} />}
              </div>
              <div className="flex items-center justify-between gap-2 font-mono text-[10px] text-ink-400">
                <span>file offset</span>
                <span className="flex items-center gap-1 text-ink-300">
                  {fileOffset ?? "unmapped"}
                  {fileOffset && <CopyButton value={fileOffset} />}
                </span>
              </div>
              {(selection.mnemonic || selection.bytes) && (
                <div className="mt-1.5 rounded border border-edge bg-obsidian-900 px-2 py-1.5 font-mono text-[10.5px]">
                  <div className="flex items-center justify-between gap-1">
                    {selection.bytes && (
                      <span className="truncate text-ink-500">{selection.bytes}</span>
                    )}
                    {selection.bytes && <CopyButton value={selection.bytes} label="bytes" />}
                  </div>
                  <div className="flex items-start justify-between gap-1">
                    <span className="min-w-0 break-words text-ink-200">
                      <span className="text-sky-300">{selection.mnemonic}</span>{" "}
                      {selection.text?.replace(selection.mnemonic ?? "", "").trim()}
                    </span>
                    {selection.text && (
                      <CopyButton value={selection.text} label="instruction" />
                    )}
                  </div>
                </div>
              )}
              {section && (
                <button
                  className="flex items-center gap-1 text-[10px] text-ink-500 transition-colors hover:text-ink-300"
                  onClick={() => navigate({ address: section.address }, "hex")}
                  title="Go to section start"
                >
                  <MapPin className="size-3" />
                  {section.name} · {section.permissions} · {formatSize(section.size)}
                </button>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center gap-1.5 py-4 text-center">
              <Sparkles className="size-5 text-ink-600" />
              <div className="text-[11px] leading-relaxed text-ink-500">
                Select an instruction, byte, symbol or string to inspect it.
              </div>
            </div>
          )}
        </section>

        {analysis && currentFunction && (
          <section className="border-b border-edge p-2.5">
            <div className="mb-1.5 flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-[9.5px] font-semibold uppercase tracking-[0.16em] text-ink-500">
                <GitFork className="size-3" />
                Function
              </span>
              <div className="flex items-center gap-1">
                {currentFunction.verified ? (
                  <span
                    className="rounded bg-emerald-500/10 px-1 font-mono text-[8.5px] uppercase text-emerald-300"
                    title={`Discovered from ${currentFunction.origin}`}
                  >
                    verified
                  </span>
                ) : (
                  <span
                    className="rounded bg-obsidian-700 px-1 font-mono text-[8.5px] uppercase text-ink-500"
                    title={`Discovered from ${currentFunction.origin}`}
                  >
                    call target
                  </span>
                )}
                <button
                  className="icon-btn size-5"
                  title="Rename function (F2)"
                  disabled={!projectPath}
                  onClick={() =>
                    requestRename(currentFunction.address)
                  }
                >
                  <Pencil className="size-3" />
                </button>
              </div>
            </div>
            <div className="space-y-1 text-[10px]">
              <div
                className="truncate font-mono text-[11.5px] text-ink-200"
                title={currentFunction.name}
              >
                {currentFunction.name}
              </div>
              <Field
                label="Address"
                copy={currentFunction.address}
              >
                {formatHex(currentFunction.address, 16)}
              </Field>
              <Field label="Range">
                {formatHex(currentFunction.address)} →{" "}
                {formatHex(currentFunction.endAddress)}
              </Field>
              <div className="grid grid-cols-3 gap-1 pt-1">
                <div className="rounded border border-edge bg-obsidian-900 px-1.5 py-1">
                  <div className="font-mono text-[10.5px] text-ink-200">
                    {currentFunction.instructionCount}
                  </div>
                  <div className="text-[8.5px] uppercase tracking-wide text-ink-600">
                    insn
                  </div>
                </div>
                <div className="rounded border border-edge bg-obsidian-900 px-1.5 py-1">
                  <div className="font-mono text-[10.5px] text-ink-200">
                    {currentFunction.blockCount}
                  </div>
                  <div className="text-[8.5px] uppercase tracking-wide text-ink-600">
                    blocks
                  </div>
                </div>
                <div className="rounded border border-edge bg-obsidian-900 px-1.5 py-1">
                  <div className="font-mono text-[10.5px] text-ink-200">
                    {currentFunction.referenceCount}
                  </div>
                  <div className="text-[8.5px] uppercase tracking-wide text-ink-600">
                    refs
                  </div>
                </div>
              </div>
              {currentFunction.callers.length > 0 && (
                <div className="pt-1">
                  <div className="mb-0.5 text-[9px] text-ink-600">
                    Callers
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {currentFunction.callers.slice(0, 5).map((caller) => (
                      <button
                        key={caller.address}
                        className="max-w-full truncate rounded border border-edge bg-obsidian-900 px-1 py-0.5 font-mono text-[9px] text-ink-300 hover:border-accent-500/40 hover:text-accent-300"
                        onClick={() => navigate({ address: caller.address })}
                        title={`${caller.name} — ${caller.address}`}
                      >
                        {caller.name}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {currentFunction.callees.length > 0 && (
                <div className="pt-1">
                  <div className="mb-0.5 text-[9px] text-ink-600">
                    Callees
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {currentFunction.callees.slice(0, 5).map((callee) => (
                      <button
                        key={callee.address}
                        className="max-w-full truncate rounded border border-edge bg-obsidian-900 px-1 py-0.5 font-mono text-[9px] text-ink-300 hover:border-accent-500/40 hover:text-accent-300"
                        onClick={() => navigate({ address: callee.address })}
                        title={`${callee.name} — ${callee.address}`}
                      >
                        {callee.name}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              <div className="flex gap-1.5 pt-1.5">
                <button
                  className="btn h-6.5 flex-1 px-2 text-[10px]"
                  onClick={() => openCfg(currentFunction.address)}
                >
                  <GitFork className="size-3" />
                  Control Flow
                </button>
                <button
                  className="btn h-6.5 flex-1 px-2 text-[10px]"
                  onClick={() => openXrefs(currentFunction.address)}
                >
                  <Share2 className="size-3" />
                  References
                </button>
              </div>
            </div>
          </section>
        )}

        {analysis && address && (
          <section className="border-b border-edge p-2.5">
            <div className="mb-1.5 flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-[9.5px] font-semibold uppercase tracking-[0.16em] text-ink-500">
                <Share2 className="size-3" />
                References
              </span>
              <button
                className="text-[9px] text-accent-400 hover:text-accent-300"
                onClick={() => openXrefs(address)}
              >
                show all
              </button>
            </div>
            {!references ? (
              <div className="text-[10px] text-ink-500">
                Resolving cross-references…
              </div>
            ) : references.incoming.length === 0 &&
              references.outgoing.length === 0 ? (
              <div className="text-[10px] text-ink-500">
                No call or jump references at this address.
              </div>
            ) : (
              <div className="space-y-1">
                {references.incoming.length > 0 && (
                  <div>
                    <div className="mb-0.5 flex items-center justify-between text-[9px] text-ink-600">
                      <span>Incoming</span>
                      <span>{references.incomingTotal}</span>
                    </div>
                    {references.incoming.map((reference, index) => (
                      <button
                        key={`in-${reference.from}-${index}`}
                        className="flex w-full items-center gap-1 rounded px-1 py-0.5 text-left font-mono text-[9.5px] hover:bg-obsidian-750"
                        onClick={() =>
                          navigate({ address: reference.from })
                        }
                        title={`${reference.from} → ${reference.to} (${reference.kind})`}
                      >
                        <span className="text-accent-400/80">
                          {formatHex(reference.from)}
                        </span>
                        <span className="text-ink-600">
                          {reference.kind === "call"
                            ? "call"
                            : reference.kind === "conditionalJump"
                              ? "jcc"
                              : "jmp"}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-right text-ink-500">
                          {reference.sourceFunction?.name ?? ""}
                        </span>
                      </button>
                    ))}
                  </div>
                )}
                {references.outgoing.length > 0 && (
                  <div>
                    <div className="mb-0.5 flex items-center justify-between text-[9px] text-ink-600">
                      <span>Outgoing</span>
                      <span>{references.outgoingTotal}</span>
                    </div>
                    {references.outgoing.map((reference, index) => (
                      <button
                        key={`out-${reference.to}-${index}`}
                        className="flex w-full items-center gap-1 rounded px-1 py-0.5 text-left font-mono text-[9.5px] hover:bg-obsidian-750"
                        onClick={() => navigate({ address: reference.to })}
                        title={`${reference.from} → ${reference.to} (${reference.kind})`}
                      >
                        <span className="text-accent-400/80">
                          {formatHex(reference.to)}
                        </span>
                        <span className="text-ink-600">
                          {reference.kind === "call"
                            ? "call"
                            : reference.kind === "conditionalJump"
                              ? "jcc"
                              : "jmp"}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-right text-ink-500">
                          {reference.targetFunction?.name ?? ""}
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </section>
        )}

        <section className="border-b border-edge p-2.5">
          <div className="mb-2 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-[9.5px] font-semibold uppercase tracking-[0.16em] text-ink-500">
              <BookMarked className="size-3" />
              Annotation
            </span>
            {existing ? (
              <span className="rounded bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[9px] text-emerald-300">
                saved #{existing.id}
              </span>
            ) : (
              <span className="font-mono text-[9px] text-ink-600">
                {projectInfo ? "new" : "project required"}
              </span>
            )}
          </div>

          {address ? (
            <div className="space-y-1.5">
              <input
                className="input"
                placeholder="Label (e.g. decrypt_payload)"
                value={label}
                onChange={(event) => setLabel(event.target.value)}
                spellCheck={false}
              />
              <textarea
                className="w-full resize-y rounded-md border border-edge-strong bg-obsidian-900 px-2 py-1.5 text-[11.5px] text-ink-100 placeholder:text-ink-600 focus:border-accent-500/70 focus:outline-none"
                rows={3}
                placeholder="Analysis note…"
                value={note}
                onChange={(event) => setNote(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                    event.preventDefault();
                    if (projectInfo) submit();
                  }
                }}
              />
              <div className="flex items-center gap-1.5">
                <button
                  className="btn-primary h-7 flex-1 px-2 text-[11px]"
                  onClick={submit}
                  disabled={!projectInfo || busy != null || !dirty}
                  title={
                    projectInfo
                      ? "Save annotation (Ctrl+Enter)"
                      : "Create or open a project first"
                  }
                >
                  <Save className="size-3.5" />
                  Save Annotation
                </button>
                {existing && (
                  <button
                    className="btn h-7 px-2 text-[11px] text-red-300 hover:border-red-500/40 hover:bg-red-500/10"
                    onClick={() => deleteAnnotation(existing.id)}
                    disabled={!projectInfo || busy != null}
                    title="Delete annotation"
                  >
                    <Trash2 className="size-3.5" />
                  </button>
                )}
              </div>
              {!projectInfo && (
                <button
                  className="flex w-full items-center justify-center gap-1.5 rounded border border-dashed border-edge-strong py-1.5 text-[10px] text-ink-400 transition-colors hover:border-accent-500/40 hover:text-accent-300"
                  onClick={newProject}
                  disabled={!binary}
                >
                  <FilePlus2 className="size-3" />
                  Create a project to persist annotations
                </button>
              )}
            </div>
          ) : (
            <div className="text-[10.5px] text-ink-500">
              An address is required to attach an annotation.
            </div>
          )}
        </section>

        <section className="border-b border-edge p-2.5">
          <div className="mb-1.5 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-[9.5px] font-semibold uppercase tracking-[0.16em] text-ink-500">
              <Database className="size-3" />
              Project
            </span>
            {projectInfo && (
              <span className="flex items-center gap-1 text-[9.5px] text-ink-400">
                {binaryStatus === "unchanged" ? (
                  <ShieldCheck className="size-3 text-emerald-400" />
                ) : (
                  <ShieldAlert className="size-3 text-amber-400" />
                )}
                {binaryStatus ?? "unknown"}
              </span>
            )}
          </div>
          {projectInfo ? (
            <div className="space-y-1 text-[10px]">
              <Field label="Name">{projectInfo.name}</Field>
              <Field label="Schema">v{projectInfo.schemaVersion}</Field>
              <Field label="Annotations">{String(annotations.length)}</Field>
              <Field label="Updated">
                {projectInfo.updatedAt.replace("T", " ").slice(0, 19)}
              </Field>
              {projectPath && (
                <div
                  className="truncate border-t border-edge/70 pt-1 font-mono text-[9px] text-ink-500"
                  title={projectPath}
                >
                  {shorten(projectPath, 18, 14)}
                </div>
              )}
              {binaryStatus === "modified" && (
                <div className="rounded border border-amber-500/25 bg-amber-500/5 px-1.5 py-1 text-[9.5px] text-amber-300/90">
                  The binary changed since this project was created. Annotations
                  may not map correctly.
                </div>
              )}
              {binaryStatus === "missing" && (
                <div className="rounded border border-red-500/25 bg-red-500/5 px-1.5 py-1 text-[9.5px] text-red-300/90">
                  The original binary is missing from its recorded path.
                </div>
              )}
            </div>
          ) : (
            <div className="text-[10.5px] leading-relaxed text-ink-500">
              No project loaded. Annotations live in a SQLite `.ura` project and
              survive restarts.
            </div>
          )}
        </section>

        {binary && (
          <section className="border-b border-edge p-2.5">
            <div className="mb-1.5 text-[9.5px] font-semibold uppercase tracking-[0.16em] text-ink-500">
              Binary
            </div>
            <div className="space-y-1 text-[10px]">
              <Field label="File" copy={binary.info.path}>
                {binary.info.fileName}
              </Field>
              <Field label="Format">
                {binary.info.format} · {binary.info.bitness}-bit
              </Field>
              <Field label="Image base" copy={binary.info.imageBase}>
                {formatHex(binary.info.imageBase, 16)}
              </Field>
              <Field label="Entry" copy={binary.info.entryPoint ?? undefined}>
                {binary.info.entryPoint ? formatHex(binary.info.entryPoint, 16) : "—"}
              </Field>
              <Field label="SHA-256" copy={binary.info.sha256}>
                {shorten(binary.info.sha256, 10, 8)}
              </Field>
            </div>
          </section>
        )}

        <section className="p-2.5">
          <div className="mb-1.5 flex items-center justify-between">
            <span className="text-[9.5px] font-semibold uppercase tracking-[0.16em] text-ink-500">
              All annotations
            </span>
            <span className="font-mono text-[9.5px] text-ink-500">
              {annotations.length}
            </span>
          </div>
          {annotations.length === 0 ? (
            <div className="rounded border border-dashed border-edge py-3 text-center text-[10px] text-ink-500">
              No annotations yet.
            </div>
          ) : (
            <div className="space-y-1">
              {annotations
                .slice()
                .reverse()
                .map((annotation) => (
                  <AnnotationSummary
                    key={annotation.id}
                    annotation={annotation}
                    active={normalizeAddress(annotation.address) === address}
                    onSelect={() => navigate({ address: annotation.address })}
                    onDelete={() => deleteAnnotation(annotation.id)}
                    canDelete={Boolean(projectInfo) && busy == null}
                  />
                ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
