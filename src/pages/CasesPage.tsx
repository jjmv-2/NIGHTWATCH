import {
  Clock3,
  FileSearch,
  FolderOpen,
  ShieldCheck,
} from "lucide-react"

import {
  useEffect,
  useState,
} from "react"

import {
  getCases,
  type ResearchCaseSummary,
} from "../services/cases"

type CasesPageProps = {
  onOpenCase: (
    caseId: string,
  ) => void
}

export default function CasesPage({
  onOpenCase,
}: CasesPageProps) {
  const [
    cases,
    setCases,
  ] = useState<
    ResearchCaseSummary[]
  >([])

  const [
    loading,
    setLoading,
  ] = useState(true)

  const [
    error,
    setError,
  ] = useState<string | null>(
    null,
  )

  useEffect(() => {
    let cancelled = false

    async function loadCases() {
      try {
        setLoading(true)
        setError(null)

        const data =
          await getCases()

        if (!cancelled) {
          setCases(data)
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : "Failed to load cases.",
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    loadCases()

    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className="cases-page">
      <div className="cases-page-header">
        <div>
          <span className="eyebrow">
            NIGHTWATCH RESEARCH
          </span>

          <h1>Cases</h1>

          <p>
            Saved investigations and
            analyst research.
          </p>
        </div>

        <div className="cases-count">
          <FolderOpen size={15} />

          <strong>
            {cases.length}
          </strong>

          <span>
            {cases.length === 1
              ? "CASE"
              : "CASES"}
          </span>
        </div>
      </div>

      {loading && (
        <div className="cases-state">
          <FileSearch size={20} />

          <strong>
            Loading Research Cases
          </strong>

          <span>
            Reading saved NIGHTWATCH
            investigations...
          </span>
        </div>
      )}

      {!loading &&
        error && (
          <div className="cases-state cases-error">
            <FileSearch size={20} />

            <strong>
              Unable to Load Cases
            </strong>

            <span>
              {error}
            </span>
          </div>
        )}

      {!loading &&
        !error &&
        cases.length === 0 && (
          <div className="cases-state">
            <FolderOpen size={22} />

            <strong>
              No Research Cases
            </strong>

            <span>
              Create a case from an
              investigation and it will
              appear here.
            </span>
          </div>
        )}

      {!loading &&
        !error &&
        cases.length > 0 && (
          <div className="cases-grid">
            {cases.map(
              (researchCase) => (
                <article
                  className="case-card"
                  key={
                    researchCase.id
                  }
                >
                  <div className="case-card-top">
                    <span className="case-status">
                      <ShieldCheck
                        size={11}
                      />

                      {researchCase.status.toUpperCase()}
                    </span>

                    <span className="case-id">
                      {researchCase.id}
                    </span>
                  </div>

                  <div className="case-card-body">
                    <h2>
                      {
                        researchCase.title
                      }
                    </h2>

                    <div className="case-indicator">
                      <span>
                        {researchCase.originalIndicatorType.toUpperCase()}
                      </span>

                      <strong>
                        {researchCase.originalIndicator}
                      </strong>
                    </div>
                  </div>

                  <div className="case-card-footer">
                    <span>
                      <Clock3
                        size={12}
                      />

                      {new Date(
                        researchCase.createdAt,
                      ).toLocaleString()}
                    </span>

                    <button
                      type="button"
                      className="open-case-button"
                      onClick={() =>
                        onOpenCase(
                          researchCase.id,
                        )
                      }
                    >
                      OPEN CASE →
                    </button>
                  </div>
                </article>
              ),
            )}
          </div>
        )}
    </div>
  )
}