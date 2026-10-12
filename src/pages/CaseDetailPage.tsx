import {
  ArrowLeft,
  CalendarDays,
  Database,
  FileSearch,
  Globe2,
  Network,
  NotebookPen,
  Pencil,
  Save,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react"

import {
  useEffect,
  useState,
} from "react"

import {
  deleteCase,
  getCase,
  updateCase,
  type ResearchCase,
} from "../services/cases"

type CaseDetailPageProps = {
  caseId: string

  onBack: () => void

  onInvestigate: (
    indicator: string,
    caseId?: string,
  ) => void
}

export default function CaseDetailPage({
  caseId,
  onBack,
  onInvestigate,
}: CaseDetailPageProps) {
  const [
    researchCase,
    setResearchCase,
  ] = useState<ResearchCase | null>(
    null,
  )

  const [loading, setLoading] =
    useState(true)

  const [error, setError] =
    useState<string | null>(null)

  const [title, setTitle] =
    useState("")

  const [notes, setNotes] =
    useState("")

  const [editingTitle, setEditingTitle] =
    useState(false)

  const [saving, setSaving] =
    useState(false)

  const [deleting, setDeleting] =
    useState(false)

  const [message, setMessage] =
    useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function loadCase() {
      try {
        setLoading(true)
        setError(null)

        const data =
          await getCase(caseId)

        if (!cancelled) {
          setResearchCase(data)
          setTitle(data.title)
          setNotes(data.notes)
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : "Failed to load case.",
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    loadCase()

    return () => {
      cancelled = true
    }
  }, [caseId])

  async function saveMetadata(
    updates: {
      title?: string
      notes?: string
      status?: "active" | "closed"
    },
  ) {
    if (!researchCase) {
      return
    }

    try {
      setSaving(true)
      setError(null)
      setMessage(null)

      const updated =
        await updateCase(
          researchCase.id,
          updates,
        )

      setResearchCase({
        ...researchCase,
        title: updated.title,
        notes: updated.notes,
        status: updated.status,
        updatedAt:
          updated.updatedAt,
      })

      setTitle(updated.title)
      setNotes(updated.notes)
      setEditingTitle(false)

      setMessage("Case updated.")
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to update case.",
      )
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete() {
    if (!researchCase) {
      return
    }

    const confirmed =
      window.confirm(
        `Delete ${researchCase.caseNumber}? This permanently removes the case and its saved intelligence.`,
      )

    if (!confirmed) {
      return
    }

    try {
      setDeleting(true)

      await deleteCase(
        researchCase.id,
      )

      onBack()
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to delete case.",
      )

      setDeleting(false)
    }
  }

  if (loading) {
    return (
      <div className="case-detail-state">
        <FileSearch size={22} />

        <strong>
          Opening Research Case
        </strong>

        <span>
          Loading saved intelligence...
        </span>
      </div>
    )
  }

  if (
    error &&
    !researchCase
  ) {
    return (
      <div className="case-detail-state">
        <ShieldAlert size={22} />

        <strong>
          Unable to Open Case
        </strong>

        <span>{error}</span>

        <button
          type="button"
          className="case-back-button"
          onClick={onBack}
        >
          <ArrowLeft size={13} />
          Back to Cases
        </button>
      </div>
    )
  }

  if (!researchCase) {
    return null
  }

  return (
    <div className="case-detail-page">
      <button
        type="button"
        className="case-back-button"
        onClick={onBack}
      >
        <ArrowLeft size={13} />
        Back to Cases
      </button>

      {error && (
        <div className="case-error-banner">
          <ShieldAlert size={15} />
          <span>{error}</span>
        </div>
      )}

      {message && (
        <div className="case-created-banner">
          <ShieldCheck size={15} />
          <span>{message}</span>
        </div>
      )}

      <section className="case-detail-header">
        <div className="case-title-area">
          <div className="case-detail-eyebrow">
            <span>
              NIGHTWATCH CASE
            </span>

            <span className="case-status">
              <ShieldCheck size={11} />

              {researchCase.status.toUpperCase()}
            </span>
          </div>

          {editingTitle ? (
            <div className="case-title-editor">
              <input
                value={title}
                onChange={(event) =>
                  setTitle(
                    event.target.value,
                  )
                }
                autoFocus
              />

              <button
                type="button"
                onClick={() =>
                  saveMetadata({
                    title,
                  })
                }
                disabled={
                  saving ||
                  !title.trim()
                }
              >
                <Save size={14} />
              </button>

              <button
                type="button"
                onClick={() => {
                  setTitle(
                    researchCase.title,
                  )

                  setEditingTitle(false)
                }}
              >
                <X size={14} />
              </button>
            </div>
          ) : (
            <div className="case-title-display">
              <h1>
                {researchCase.title}
              </h1>

              <button
                type="button"
                onClick={() =>
                  setEditingTitle(true)
                }
                title="Edit case title"
              >
                <Pencil size={14} />
              </button>
            </div>
          )}

          <span className="case-detail-id">
            {researchCase.caseNumber}
          </span>
        </div>

        <div className="case-management-actions">
          <button
            type="button"
            className="primary-small-button"
            onClick={() =>
              onInvestigate(
                researchCase.originalIndicator,
                researchCase.id,
              )
            }
          >
            <FileSearch size={14} />
            Continue Investigation
          </button>

          <button
            type="button"
            className="secondary-button"
            disabled={saving}
            onClick={() =>
              saveMetadata({
                status:
                  researchCase.status ===
                  "active"
                    ? "closed"
                    : "active",
              })
            }
          >
            {researchCase.status ===
            "active"
              ? "Close Case"
              : "Reopen Case"}
          </button>

          <button
            type="button"
            className="case-delete-button"
            disabled={deleting}
            onClick={handleDelete}
          >
            <Trash2 size={14} />

            {deleting
              ? "Deleting..."
              : "Delete"}
          </button>
        </div>
      </section>

      <section className="case-detail-summary">
        <div className="case-summary-card">
          <Globe2 size={15} />

          <span>
            ORIGINAL INDICATOR
          </span>

          <strong>
            {researchCase.originalIndicator}
          </strong>

          <small>
            {researchCase.originalIndicatorType.toUpperCase()}
          </small>
        </div>

        <div className="case-summary-card">
          <CalendarDays size={15} />

          <span>CREATED</span>

          <strong>
            {new Date(
              researchCase.createdAt,
            ).toLocaleString()}
          </strong>
        </div>

        <div className="case-summary-card">
          <Network size={15} />

          <span>INDICATORS</span>

          <strong>
            {researchCase.indicators.length}
          </strong>
        </div>

        <div className="case-summary-card">
          <ShieldAlert size={15} />

          <span>FINDINGS</span>

          <strong>
            {researchCase.observations.length}
          </strong>
        </div>
      </section>

      <div className="case-detail-layout">
        <div className="case-detail-main">
          <section className="research-panel">
            <div className="panel-header">
              <div>
                <h2>
                  <Network size={15} />
                  Investigation Trail
                </h2>

                <p>
                  Intelligence pivots preserved
                  in this case.
                </p>
              </div>
            </div>

            {researchCase.indicators.length ===
            0 ? (
              <div className="case-empty">
                No saved indicators.
              </div>
            ) : (
              <div className="saved-trail">
                {researchCase.indicators.map(
                  (
                    indicator,
                    index,
                  ) => (
                    <div
                      className="saved-trail-step"
                      key={`${indicator.value}-${index}`}
                    >
                      {index > 0 && (
                        <span className="saved-trail-arrow">
                          →
                        </span>
                      )}

                      <button
                        type="button"
                        className="saved-trail-node"
                        onClick={() =>
                          onInvestigate(
                            indicator.value,
                            researchCase.id,
                          )
                        }
                      >
                        <span>
                          {indicator.type.toUpperCase()}
                        </span>

                        <strong>
                          {indicator.value}
                        </strong>
                      </button>
                    </div>
                  ),
                )}
              </div>
            )}
          </section>

          <section className="research-panel">
            <div className="panel-header">
              <div>
                <h2>
                  <ShieldAlert size={15} />
                  Saved Intelligence
                </h2>

                <p>
                  Intelligence accumulated
                  across this case.
                </p>
              </div>
            </div>

            {researchCase.observations.length ===
            0 ? (
              <div className="case-empty">
                No threat observations
                are stored.
              </div>
            ) : (
              <div className="case-findings">
                {researchCase.observations.map(
                  (
                    observation,
                    index,
                  ) => (
                    <article
                      className="case-finding"
                      key={`${observation.source}-${index}`}
                    >
                      <div className="case-finding-header">
                        <div>
                          <span>
                            {observation.type}
                          </span>

                          <strong>
                            {observation.description}
                          </strong>
                        </div>

                        <span className="case-source-badge">
                          {observation.source}
                        </span>
                      </div>

                      <div className="case-finding-grid">
                        <div>
                          <span>MALWARE</span>

                          <strong>
                            {observation.malware ||
                              "Not identified"}
                          </strong>
                        </div>

                        <div>
                          <span>
                            CONFIDENCE
                          </span>

                          <strong>
                            {typeof observation.confidence ===
                            "number"
                              ? `${observation.confidence}%`
                              : "Unknown"}
                          </strong>
                        </div>

                        <div>
                          <span>
                            FIRST SEEN
                          </span>

                          <strong>
                            {observation.firstSeen
                              ? new Date(
                                  observation.firstSeen,
                                ).toLocaleString()
                              : "Unknown"}
                          </strong>
                        </div>

                        <div>
                          <span>
                            LAST SEEN
                          </span>

                          <strong>
                            {observation.lastSeen
                              ? new Date(
                                  observation.lastSeen,
                                ).toLocaleString()
                              : "Unknown"}
                          </strong>
                        </div>
                      </div>

                      {!!observation.tags?.length && (
                        <div className="case-tags">
                          {observation.tags.map(
                            (
                              tag,
                              tagIndex,
                            ) => (
                              <span
                                key={`${tag}-${tagIndex}`}
                              >
                                {tag}
                              </span>
                            ),
                          )}
                        </div>
                      )}
                    </article>
                  ),
                )}
              </div>
            )}
          </section>

          <section className="research-panel">
            <div className="panel-header">
              <div>
                <h2>
                  <Globe2 size={15} />
                  Relationships
                </h2>

                <p>
                  Relationships accumulated
                  across the investigation.
                </p>
              </div>
            </div>

            {researchCase.relationships.length ===
            0 ? (
              <div className="case-empty">
                No relationships stored.
              </div>
            ) : (
              <div className="case-relationships">
                {researchCase.relationships.map(
                  (
                    relationship,
                    index,
                  ) => (
                    <div
                      className="case-relationship"
                      key={`${relationship.to}-${index}`}
                    >
                      <div>
                        <span>
                          {relationship.source}
                        </span>

                        <small>
                          {relationship.relationship}
                        </small>
                      </div>

                      <strong>
                        {relationship.to}
                      </strong>

                      {relationship.nodeType !==
                        "malware" && (
                        <button
                          type="button"
                          onClick={() =>
                            onInvestigate(
                              relationship.to,
                              researchCase.id,
                            )
                          }
                        >
                          INVESTIGATE →
                        </button>
                      )}
                    </div>
                  ),
                )}
              </div>
            )}
          </section>
        </div>

        <aside className="case-detail-side">
          <section className="research-panel">
            <div className="panel-header compact">
              <div>
                <h2>
                  <NotebookPen size={15} />
                  Analyst Notes
                </h2>
              </div>
            </div>

            <textarea
              className="research-notes"
              placeholder="Record analyst observations, questions, and conclusions..."
              value={notes}
              onChange={(event) =>
                setNotes(
                  event.target.value,
                )
              }
            />

            <button
              type="button"
              className="save-note-button"
              disabled={
                saving ||
                notes ===
                  researchCase.notes
              }
              onClick={() =>
                saveMetadata({
                  notes,
                })
              }
            >
              <Save size={13} />

              {saving
                ? "Saving..."
                : "Save Notes"}
            </button>
          </section>

          <section className="research-panel">
            <div className="panel-header compact">
              <div>
                <h2>
                  <Database size={15} />
                  Intelligence Sources
                </h2>
              </div>
            </div>

            {researchCase.sources.length ===
            0 ? (
              <div className="case-empty">
                No source information
                stored.
              </div>
            ) : (
              <div className="source-list">
                {researchCase.sources.map(
                  (source) => (
                    <div
                      className="source-row"
                      key={source.name}
                    >
                      <div>
                        <span
                          className={`source-dot source-${source.status}`}
                        />

                        <strong>
                          {source.name}
                        </strong>
                      </div>

                      <span
                        className={`source-status source-status-${source.status}`}
                      >
                        {source.status
                          .replace(
                            "_",
                            " ",
                          )
                          .toUpperCase()}
                      </span>
                    </div>
                  ),
                )}
              </div>
            )}
          </section>
        </aside>
      </div>
    </div>
  )
}