import {
  AlertTriangle,
  Building2,
  CalendarDays,
  CheckCircle2,
  CircleAlert,
  Clock3,
  Copy,
  Database,
  ExternalLink,
  FileSearch,
  Globe2,
  LoaderCircle,
  MapPin,
  Network,
  NotebookPen,
  Radar,
  Server,
  ShieldAlert,
  ShieldQuestion,
  ChevronRight,
} from "lucide-react"

import {
  appendInvestigationToCase,
  createCase,
} from "../services/cases"

import {
  useEffect,
  useState,
} from "react"

import {
  investigateIndicator,
  type InvestigationResponse,
} from "../services/intelligence"

import type {
  InvestigationTrailItem,
} from "../types/app"

type InvestigatePageProps = {
  indicator: string
  onPivot: (indicator: string) => void
  investigationTrail: InvestigationTrailItem[]
  activeCaseId?: string | null
}

export default function InvestigatePage({
  indicator,
  onPivot,
  investigationTrail,
  activeCaseId = null,
}: InvestigatePageProps) {
  const [result, setResult] =
    useState<InvestigationResponse | null>(
      null,
    )

  const [loading, setLoading] =
    useState(true)

  const [error, setError] =
    useState<string | null>(null)
const [
  notes,
  setNotes,
] = useState("")

const [
  creatingCase,
  setCreatingCase,
] = useState(false)

const [
  createdCase,
  setCreatedCase,
] = useState<{
  id: string
  caseNumber?: string
  title: string
} | null>(null)

const [
  addedToCase,
  setAddedToCase,
] = useState(false)

const [
  caseError,
  setCaseError,
] = useState<string | null>(
  null,
)
  useEffect(() => {
    let cancelled = false

    async function investigate() {
      setLoading(true)
      setError(null)
      setResult(null)
      setCreatedCase(null)
      setAddedToCase(false)
      setCaseError(null)

      try {
        const data =
          await investigateIndicator(
            indicator,
          )

        if (!cancelled) {
          setResult(data)
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : "Investigation failed.",
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    investigate()

    return () => {
      cancelled = true
    }
  }, [indicator])

  function copyIndicator() {
    navigator.clipboard.writeText(
      indicator,
    )
  }

  async function handleSaveResearch() {
    if (!result || creatingCase) {
      return
    }

    setCreatingCase(true)
    setCaseError(null)

    try {
      if (activeCaseId) {
        await appendInvestigationToCase(
          activeCaseId,
          result,
          investigationTrail,
        )

        setAddedToCase(true)
        return
      }

      const created =
        await createCase({
          investigation: result,
          trail: investigationTrail,
          notes,
        })

      setCreatedCase({
        id: created.id,
        caseNumber: created.caseNumber,
        title: created.title,
      })
    } catch (err) {
      setCaseError(
        err instanceof Error
          ? err.message
          : "Failed to save research.",
      )
    } finally {
      setCreatingCase(false)
    }
  }

  if (loading) {
    return (
      <div className="investigate-page">
        <div className="research-loading">
          <div className="research-loading-icon">
            <LoaderCircle
              size={25}
              className="spinner"
            />
          </div>

          <span className="eyebrow">
            NIGHTWATCH RESEARCH
          </span>

          <h1>
            Researching Indicator
          </h1>

          <strong>
            {indicator}
          </strong>

          <p>
            Validating the indicator and
            querying connected intelligence
            providers.
          </p>

          <div className="research-progress">
            <div />
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="investigate-page">
        <div className="research-error">
          <AlertTriangle size={22} />

          <h2>
            Investigation Failed
          </h2>

          <p>{error}</p>
        </div>
      </div>
    )
  }

  if (!result) {
    return null
  }

  const infrastructureCount =
    result.infrastructure.ips.length +
    result.infrastructure.domains.length +
    result.infrastructure.asns.length

  const hasIntelligence =
    infrastructureCount > 0 ||
    result.malware.length > 0 ||
    result.observations.length > 0 ||
    result.evidence.length > 0

  const maliciousEvidence =
    result.evidence.filter(
      (item) =>
        item.verdict === "malicious",
    )

  const dns =
    result.infrastructure.dns

  const otxMalwareFamilies =
    Array.from(
      new Set(
        result.otx.pulses.flatMap(
          (pulse) => pulse.malwareFamilies,
        ),
      ),
    )

  const otxAdversaries =
    Array.from(
      new Set(
        result.otx.pulses
          .map((pulse) => pulse.adversary)
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

  const otxTags =
    Array.from(
      new Set(
        result.otx.pulses.flatMap(
          (pulse) => pulse.tags,
        ),
      ),
    )

  const recentOtxPulses =
    [...result.otx.pulses]
      .sort((a, b) => {
        const aTime = a.modified || a.created
        const bTime = b.modified || b.created

        return (
          (bTime ? new Date(bTime).getTime() : 0) -
          (aTime ? new Date(aTime).getTime() : 0)
        )
      })
      .slice(0, 3)

  const threatFoxObservations =
    result.observations.filter(
      (observation) =>
        observation.source === "ThreatFox",
    )

  const urlhausObservations =
    result.observations.filter(
      (observation) =>
        observation.source === "URLhaus",
    )

  const threatFoxMalware =
    Array.from(
      new Set(
        threatFoxObservations
          .map(
            (observation) =>
              observation.malware,
          )
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

  const threatFoxThreatTypes =
    Array.from(
      new Set(
        threatFoxObservations
          .map(
            (observation) =>
              observation.type,
          )
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

  const urlhausThreatTypes =
    Array.from(
      new Set(
        urlhausObservations
          .map(
            (observation) =>
              observation.type,
          )
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

  const threatFoxSource =
    result.sources.find(
      (source) =>
        source.name === "ThreatFox",
    )

  const urlhausSource =
    result.sources.find(
      (source) =>
        source.name === "URLhaus",
    )

  const firstSeenDates =
    result.observations
      .map(
        (observation) =>
          observation.firstSeen,
      )
      .filter(
        (
          value,
        ): value is string =>
          typeof value === "string" &&
          value.length > 0,
      )
      .map(
        (value) =>
          new Date(value),
      )
      .filter(
        (date) =>
          !Number.isNaN(
            date.getTime(),
          ),
      )

  const earliestFirstSeen =
    firstSeenDates.length > 0
      ? new Date(
          Math.min(
            ...firstSeenDates.map(
              (date) =>
                date.getTime(),
            ),
          ),
        )
      : null

  const reputationClass =
    result.assessment.reputation ===
    "malicious"
      ? "malicious-badge"
      : result.assessment.reputation ===
          "suspicious"
        ? "suspicious-badge"
        : "unknown-badge"

  return (
    <div className="investigate-page">

      {/* LIVE API STATUS */}

      <div className="live-banner">
        <CheckCircle2 size={14} />

        <span>
          NIGHTWATCH LIVE — Research
          completed using connected
          intelligence providers.
        </span>
      </div>
      {/* INVESTIGATION TRAIL */}

      {investigationTrail.length > 0 && (
        <div className="investigation-trail">
          <div className="trail-heading">
            <Network size={13} />

            <span>
              INVESTIGATION TRAIL
            </span>
          </div>

          <div className="trail-items">
            {investigationTrail.map(
              (item, index) => {
                const isCurrent =
                  index ===
                  investigationTrail.length - 1

                return (
                  <div
                    className="trail-step"
                    key={`${item.value}-${index}`}
                  >
                    {index > 0 && (
                      <span className="trail-arrow">
                        →
                      </span>
                    )}

                    <button
                      type="button"
                      className={`trail-node ${
                        isCurrent
                          ? "trail-node-current"
                          : ""
                      }`}
                      onClick={() => {
                        if (!isCurrent) {
                          onPivot(item.value)
                        }
                      }}
                      disabled={isCurrent}
                      title={
                        isCurrent
                          ? "Current research target"
                          : `Return to ${item.value}`
                      }
                    >
                      <span className="trail-node-type">
                        {item.type.toUpperCase()}
                      </span>

                      <strong>
                        {item.value}
                      </strong>
                    </button>
                  </div>
                )
              },
            )}
          </div>
        </div>
      )}

      {/* HEADER */}

      <section className="research-header">
        <div>
          <div className="eyebrow">
            RESEARCH OVERVIEW
          </div>

          <div className="research-title-row">
            <h1>
              {result.indicator.value}
            </h1>

            <button
              className="copy-button"
              onClick={copyIndicator}
              title="Copy indicator"
            >
              <Copy size={14} />
            </button>
          </div>

          <div className="indicator-meta">
            <span className="indicator-type">
              {result.indicator.type.toUpperCase()}
            </span>

            <span
              className={
                reputationClass
              }
            >
              <span />

              {result.assessment.reputation.toUpperCase()}
            </span>

            <span className="confidence-label">
              {result.assessment.confidence.toUpperCase()}
              {" "}
              CONFIDENCE
            </span>
          </div>
        </div>

        <div className="research-actions">
          <button className="secondary-button">
            <NotebookPen size={14} />
            Add Note
          </button>

          <button
            className="primary-small-button"
            onClick={handleSaveResearch}
            disabled={
              creatingCase ||
              createdCase !== null ||
              addedToCase
            }
          >
            {creatingCase ? (
              <LoaderCircle
                size={14}
                className="spinner"
              />
            ) : createdCase || addedToCase ? (
              <CheckCircle2 size={14} />
            ) : (
              <FileSearch size={14} />
            )}

            {creatingCase
              ? "Saving..."
              : addedToCase
                ? "Added to Case"
                : createdCase
                  ? "Case Created"
                  : activeCaseId
                    ? "Add to Case"
                    : "Create Case"}
          </button>
        </div>
      </section>

      {/* CASE STATUS */}

      {createdCase && (
        <div className="case-created-banner">
          <CheckCircle2 size={15} />

          <div>
            <strong>
              Research Case Created
            </strong>

            <span>
              {createdCase.title}
              {" • "}
              {createdCase.caseNumber ||
                createdCase.id}
            </span>
          </div>
        </div>
      )}

      {addedToCase && (
        <div className="case-created-banner">
          <CheckCircle2 size={15} />

          <div>
            <strong>
              Intelligence Added to Case
            </strong>

            <span>
              This indicator, its findings,
              relationships, and source status
              were preserved in the active
              NIGHTWATCH case.
            </span>
          </div>
        </div>
      )}

      {caseError && (
        <div className="case-error-banner">
          <AlertTriangle size={15} />

          <span>
            {caseError}
          </span>
        </div>
      )}

      {/* TABS */}

      <div className="research-tabs">
        <button className="research-tab active">
          Overview
        </button>

        <button className="research-tab">
          Infrastructure
        </button>

        <button className="research-tab">
          Threat Intel
        </button>

        <button className="research-tab">
          Sources
        </button>
      </div>

      {/* SUMMARY */}

      <section className="summary-grid">
        <div className="intel-card">
          <div className="intel-card-icon">
            <CalendarDays size={16} />
          </div>

          <div>
            <span>
              FIRST SEEN
            </span>

            <strong>
              {earliestFirstSeen
                ? earliestFirstSeen
                    .toLocaleString()
                : "Not observed"}
            </strong>
          </div>
        </div>

        <div className="intel-card">
          <div className="intel-card-icon">
            <Clock3 size={16} />
          </div>

          <div>
            <span>
              INVESTIGATED
            </span>

            <strong>
              {new Date(
                result.investigatedAt,
              ).toLocaleString()}
            </strong>
          </div>
        </div>

        <div className="intel-card">
          <div className="intel-card-icon">
            {result.assessment
              .reputation ===
            "malicious" ? (
              <ShieldAlert
                size={16}
              />
            ) : (
              <ShieldQuestion
                size={16}
              />
            )}
          </div>

          <div>
            <span>
              REPUTATION
            </span>

            <strong>
              {result.assessment.reputation.toUpperCase()}
            </strong>
          </div>
        </div>

        <div className="intel-card">
          <div className="intel-card-icon">
            <Radar size={16} />
          </div>

          <div>
            <span>
              SOURCES
            </span>

            <strong>
              {result.sources.length}
              {" "}
              {result.sources.length ===
              1
                ? "Source"
                : "Sources"}
            </strong>
          </div>
        </div>
      </section>

      {/* NIGHTWATCH EVIDENCE ASSESSMENT */}

      <section className="research-panel nightwatch-evidence-overview">
        <div className="panel-header">
          <div>
            <span className="eyebrow">
              NIGHTWATCH ASSESSMENT
            </span>

            <h2>
              <ShieldAlert size={16} />
              Why This IOC Is{" "}
              {result.assessment.reputation === "malicious"
                ? "Malicious"
                : result.assessment.reputation === "suspicious"
                  ? "Suspicious"
                  : "Unresolved"}
            </h2>

            <p>{result.assessment.summary}</p>
          </div>
        </div>

        <div className="evidence-summary-grid">
          <div className="data-field">
            <span>MALICIOUS SIGNALS</span>
            <strong>{result.assessment.maliciousEvidenceCount}</strong>
          </div>

          <div className="data-field">
            <span>TOTAL EVIDENCE</span>
            <strong>{result.assessment.evidenceCount}</strong>
          </div>

          <div className="data-field">
            <span>CORROBORATING SOURCES</span>
            <strong>{result.assessment.corroboratingSources}</strong>
          </div>

          <div className="data-field">
            <span>ASSESSMENT CONFIDENCE</span>
            <strong>{result.assessment.confidence.toUpperCase()}</strong>
          </div>
        </div>

        {result.evidence.length === 0 ? (
          <div className="empty-panel">
            <ShieldQuestion size={19} />
            <strong>No Direct Malicious Evidence</strong>
            <span>
              Connected providers did not return direct malicious evidence
              for this IOC. This does not establish that the indicator is
              benign.
            </span>
          </div>
        ) : (
          <div className="threat-findings">
            {result.evidence.map((evidence, index) => (
              <article
                className="threat-finding-card"
                key={evidence.id}
              >
                <div className="finding-header">
                  <div className="finding-heading">
                    <div className="finding-icon">
                      {evidence.verdict === "malicious" ? (
                        <ShieldAlert size={18} />
                      ) : (
                        <ShieldQuestion size={18} />
                      )}
                    </div>

                    <div>
                      <span className="finding-label">
                        EVIDENCE {String(index + 1).padStart(2, "0")}
                        {" • "}
                        {evidence.strength.toUpperCase()}
                      </span>

                      <h3>{evidence.title}</h3>
                    </div>
                  </div>

                  <span className="finding-source">
                    {evidence.source}
                  </span>
                </div>

                <p>{evidence.description}</p>

                {evidence.details.length > 0 && (
                  <div className="finding-grid">
                    {evidence.details.map((detail) => (
                      <div
                        className="finding-field"
                        key={`${evidence.id}-${detail.label}`}
                      >
                        <span>{detail.label}</span>
                        <strong>{detail.value}</strong>
                      </div>
                    ))}
                  </div>
                )}

                <div className="finding-assessment">
                  <CircleAlert size={16} />
                  <div>
                    <strong>Why This Matters</strong>
                    <p>{evidence.explanation}</p>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}

        {maliciousEvidence.length > 0 && (
          <div className="finding-assessment">
            <CheckCircle2 size={16} />
            <div>
              <strong>Evidence-Based Classification</strong>
              <p>
                NIGHTWATCH classified this IOC from source-attributed
                evidence above. Infrastructure data such as DNS resolution
                is shown separately as context and is not treated as
                malicious by itself.
              </p>
            </div>
          </div>
        )}
      </section>

      {/* NO INTELLIGENCE */}

      {!hasIntelligence && (
        <section className="no-intelligence">
          <div className="no-intelligence-icon">
            <CircleAlert size={21} />
          </div>

          <div>
            <span className="eyebrow">
              ENRICHMENT STATUS
            </span>

            <h2>
              No Intelligence Found
            </h2>

            <p>
              Connected intelligence
              providers returned no current
              observations for this
              indicator. An unknown result
              does not mean the indicator
              is safe.
            </p>
          </div>
        </section>
      )}

      <div className="research-layout">

        {/* LEFT COLUMN */}

        <div className="research-column">

          {/* INFRASTRUCTURE */}

          <section className="research-panel">
            <div className="panel-header">
              <div>
                <h2>
                  <Network size={15} />
                  Infrastructure
                </h2>

                <p>
                  Hosting and network
                  infrastructure discovered
                  during enrichment.
                </p>
              </div>
            </div>

            <div className="infrastructure-grid">

              <div className="data-field">
                <span>
                  <Server size={13} />
                  IP ADDRESSES
                </span>

                <strong>
                  {result.infrastructure
                    .ips.length > 0
                    ? result
                        .infrastructure
                        .ips.join(", ")
                    : "No observations"}
                </strong>
              </div>

              <div className="data-field">
                <span>
                  <Network size={13} />
                  ASN
                </span>

                <strong>
                  {result.infrastructure
                    .asns.length > 0
                    ? result
                        .infrastructure
                        .asns.join(", ")
                    : "No observations"}
                </strong>
              </div>

              <div className="data-field">
                <span>
                  <Building2 size={13} />
                  PROVIDER
                </span>

                <strong>
                  {result.infrastructure
                    .providers.length > 0
                    ? result
                        .infrastructure
                        .providers.join(", ")
                    : "No observations"}
                </strong>
              </div>

              <div className="data-field">
                <span>
                  <MapPin size={13} />
                  COUNTRY
                </span>

                <strong>
                  {result.infrastructure
                    .countries.length > 0
                    ? result
                        .infrastructure
                        .countries.join(", ")
                    : "No observations"}
                </strong>
              </div>

            </div>

            <div className="finding-assessment">
              <Network size={16} />
              <div>
                <strong>Infrastructure Context</strong>
                <p>
                  DNS and hosting relationships describe where an IOC
                  resolves or connects. They are investigative context,
                  not proof of maliciousness by themselves.
                </p>
              </div>
            </div>

            {result.infrastructure.bgp.length > 0 && (
              <div className="threat-findings">
                {result.infrastructure.bgp.map((route) => (
                  <article
                    className="threat-finding-card"
                    key={`bgp-${route.ip}`}
                  >
                    <div className="finding-header">
                      <div className="finding-heading">
                        <div className="finding-icon">
                          <Network size={18} />
                        </div>

                        <div>
                          <span className="finding-label">
                            ROUTING CONTEXT • BGP
                          </span>
                          <h3>{route.ip}</h3>
                        </div>
                      </div>

                      <span className="finding-source">
                        RIPEstat
                      </span>
                    </div>

                    <div className="finding-grid">
                      <div className="finding-field">
                        <span>ANNOUNCED PREFIX</span>
                        <strong>
                          {route.prefix || "Not observed"}
                        </strong>
                      </div>

                      <div className="finding-field">
                        <span>ORIGIN ASN</span>
                        <strong>
                          {route.asns.length > 0
                            ? route.asns
                                .map((asn) => `AS${asn}`)
                                .join(", ")
                            : "Not observed"}
                        </strong>
                      </div>

                      <div className="finding-field">
                        <span>AS HOLDER</span>
                        <strong>
                          {route.asHolder || "Not provided"}
                        </strong>
                      </div>

                      <div className="finding-field">
                        <span>IP</span>
                        <strong>{route.ip}</strong>
                      </div>
                    </div>

                    <div className="finding-assessment">
                      <CircleAlert size={16} />
                      <div>
                        <strong>What This Means</strong>
                        <p>
                          RIPEstat routing data maps this IP to an
                          announced network prefix and observed origin
                          ASN. This is routing context, not evidence that
                          the ASN or network operator is malicious.
                        </p>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            )}

            {result.infrastructure.rdap.length > 0 && (
              <div className="threat-findings">
                {result.infrastructure.rdap.map((network) => (
                  <article
                    className="threat-finding-card"
                    key={`rdap-${network.ip}`}
                  >
                    <div className="finding-header">
                      <div className="finding-heading">
                        <div className="finding-icon">
                          <Server size={18} />
                        </div>

                        <div>
                          <span className="finding-label">
                            REGISTERED NETWORK • RDAP
                          </span>
                          <h3>{network.ip}</h3>
                        </div>
                      </div>

                      <span className="finding-source">
                        {network.registry || "RDAP"}
                      </span>
                    </div>

                    <div className="finding-grid">
                      <div className="finding-field">
                        <span>NETWORK NAME</span>
                        <strong>
                          {network.name || "Not provided"}
                        </strong>
                      </div>

                      <div className="finding-field">
                        <span>ORGANIZATION</span>
                        <strong>
                          {network.organization || "Not provided"}
                        </strong>
                      </div>

                      <div className="finding-field">
                        <span>NETWORK RANGE</span>
                        <strong>
                          {network.startAddress && network.endAddress
                            ? `${network.startAddress} — ${network.endAddress}`
                            : "Not provided"}
                        </strong>
                      </div>

                      <div className="finding-field">
                        <span>CIDR</span>
                        <strong>
                          {network.cidrs.length > 0
                            ? network.cidrs.join(", ")
                            : "Not provided"}
                        </strong>
                      </div>

                      <div className="finding-field">
                        <span>COUNTRY</span>
                        <strong>
                          {network.country || "Not provided"}
                        </strong>
                      </div>

                      <div className="finding-field">
                        <span>REGISTRY</span>
                        <strong>
                          {network.registry || "Not provided"}
                        </strong>
                      </div>

                      <div className="finding-field">
                        <span>REGISTRATION</span>
                        <strong>
                          {network.registrationDate
                            ? new Date(
                                network.registrationDate,
                              ).toLocaleString()
                            : "Not provided"}
                        </strong>
                      </div>

                      <div className="finding-field">
                        <span>LAST CHANGED</span>
                        <strong>
                          {network.lastChangedDate
                            ? new Date(
                                network.lastChangedDate,
                              ).toLocaleString()
                            : "Not provided"}
                        </strong>
                      </div>
                    </div>

                    <div className="finding-assessment">
                      <CircleAlert size={16} />
                      <div>
                        <strong>What This Means</strong>
                        <p>
                          RDAP identifies the registered network and
                          organization associated with this IP range.
                          This is ownership and registration context,
                          not malicious evidence and not proof of the
                          IP&apos;s current BGP origin ASN.
                        </p>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            )}

            <div className="finding-grid">
              <div className="finding-field">
                <span>DNS A RECORDS</span>
                <strong>
                  {dns.a.length > 0 ? dns.a.join(", ") : "No records"}
                </strong>
              </div>

              <div className="finding-field">
                <span>DNS AAAA RECORDS</span>
                <strong>
                  {dns.aaaa.length > 0 ? dns.aaaa.join(", ") : "No records"}
                </strong>
              </div>

              <div className="finding-field">
                <span>NAMESERVERS</span>
                <strong>
                  {dns.ns.length > 0 ? dns.ns.join(", ") : "No records"}
                </strong>
              </div>

              <div className="finding-field">
                <span>CNAME</span>
                <strong>
                  {dns.cname.length > 0 ? dns.cname.join(", ") : "No records"}
                </strong>
              </div>

              <div className="finding-field">
                <span>MAIL EXCHANGERS</span>
                <strong>
                  {dns.mx.length > 0
                    ? dns.mx
                        .map(
                          (record) =>
                            `${record.exchange} (${record.priority})`,
                        )
                        .join(", ")
                    : "No records"}
                </strong>
              </div>

              <div className="finding-field">
                <span>REVERSE DNS</span>
                <strong>
                  {dns.reverse.length > 0
                    ? dns.reverse.join(", ")
                    : "No records"}
                </strong>
              </div>
            </div>
          </section>

          {/* THREATFOX INTELLIGENCE */}

          {threatFoxSource?.evidenceFound && (
            <section className="research-panel">
              <div className="panel-header">
                <div>
                  <h2>
                    <ShieldAlert size={15} />
                    ThreatFox Intelligence
                  </h2>

                  <p>
                    Consolidated abuse.ch IOC intelligence associated
                    with this indicator.
                  </p>
                </div>

                <span className="finding-source">
                  {threatFoxSource.evidenceCount}{" "}
                  {threatFoxSource.evidenceCount === 1
                    ? "RECORD"
                    : "RECORDS"}
                </span>
              </div>

              <div className="finding-grid">
                <div className="finding-field">
                  <span>IOC RECORDS</span>
                  <strong>{threatFoxSource.evidenceCount}</strong>
                </div>

                <div className="finding-field">
                  <span>THREAT TYPES</span>
                  <strong>
                    {threatFoxThreatTypes.length > 0
                      ? threatFoxThreatTypes.slice(0, 4).join(", ") +
                        (threatFoxThreatTypes.length > 4
                          ? ` +${threatFoxThreatTypes.length - 4} more`
                          : "")
                      : "Not identified"}
                  </strong>
                </div>

                <div className="finding-field">
                  <span>MALWARE FAMILIES</span>
                  <strong>
                    {threatFoxMalware.length > 0
                      ? threatFoxMalware.slice(0, 4).join(", ") +
                        (threatFoxMalware.length > 4
                          ? ` +${threatFoxMalware.length - 4} more`
                          : "")
                      : "Not identified"}
                  </strong>
                </div>

                <div className="finding-field">
                  <span>SOURCE STRENGTH</span>
                  <strong>STRONG</strong>
                </div>
              </div>

              {threatFoxSource.contribution.length > 0 && (
                <div className="source-contribution-list">
                  {threatFoxSource.contribution
                    .slice(0, 4)
                    .map((item) => (
                      <span key={`threatfox-summary-${item}`}>
                        <ChevronRight size={11} />
                        {item}
                      </span>
                    ))}
                </div>
              )}

              <div className="finding-assessment">
                <CheckCircle2 size={16} />
                <div>
                  <strong>Why This Matters</strong>
                  <p>
                    ThreatFox directly tracks indicators reported in
                    malicious activity. NIGHTWATCH groups all matching
                    ThreatFox records into one strong evidence signal so
                    repeated records add context without inflating
                    independent-source corroboration.
                  </p>
                </div>
              </div>
            </section>
          )}

          {/* URLHAUS INTELLIGENCE */}

          {urlhausSource?.evidenceFound && (
            <section className="research-panel">
              <div className="panel-header">
                <div>
                  <h2>
                    <Globe2 size={15} />
                    URLhaus Intelligence
                  </h2>

                  <p>
                    Consolidated abuse.ch malware-distribution
                    intelligence associated with this indicator.
                  </p>
                </div>

                <span className="finding-source">
                  {urlhausSource.evidenceCount}{" "}
                  {urlhausSource.evidenceCount === 1
                    ? "RECORD"
                    : "RECORDS"}
                </span>
              </div>

              <div className="finding-grid">
                <div className="finding-field">
                  <span>MATCHING RECORDS</span>
                  <strong>{urlhausSource.evidenceCount}</strong>
                </div>

                <div className="finding-field">
                  <span>THREAT TYPES</span>
                  <strong>
                    {urlhausThreatTypes.length > 0
                      ? urlhausThreatTypes.slice(0, 4).join(", ") +
                        (urlhausThreatTypes.length > 4
                          ? ` +${urlhausThreatTypes.length - 4} more`
                          : "")
                      : "Malware distribution"}
                  </strong>
                </div>

                <div className="finding-field">
                  <span>PROVIDER</span>
                  <strong>abuse.ch URLhaus</strong>
                </div>

                <div className="finding-field">
                  <span>SOURCE STRENGTH</span>
                  <strong>STRONG</strong>
                </div>
              </div>

              {urlhausSource.contribution.length > 0 && (
                <div className="source-contribution-list">
                  {urlhausSource.contribution
                    .slice(0, 4)
                    .map((item) => (
                      <span key={`urlhaus-summary-${item}`}>
                        <ChevronRight size={11} />
                        {item}
                      </span>
                    ))}
                </div>
              )}

              <div className="finding-assessment">
                <CheckCircle2 size={16} />
                <div>
                  <strong>Why This Matters</strong>
                  <p>
                    URLhaus tracks infrastructure used to distribute
                    malware. NIGHTWATCH consolidates matching URLhaus
                    records into one strong evidence signal while keeping
                    the provider independent from ThreatFox for
                    provenance and corroboration.
                  </p>
                </div>
              </div>
            </section>
          )}

          {/* OTX PULSE INTELLIGENCE */}

          {result.otx.pulses.length > 0 && (
            <section className="research-panel">
              <div className="panel-header">
                <div>
                  <h2>
                    <Radar size={15} />
                    OTX Pulse Intelligence
                  </h2>

                  <p>
                    Consolidated OTX context. Pulse matches are grouped
                    together instead of displayed as separate evidence cards.
                  </p>
                </div>

                <span className="finding-source">
                  {result.otx.pulseCount}{" "}
                  {result.otx.pulseCount === 1 ? "PULSE" : "PULSES"}
                </span>
              </div>

              <div className="finding-grid">
                <div className="finding-field">
                  <span>PULSE MATCHES</span>
                  <strong>{result.otx.pulseCount}</strong>
                </div>

                <div className="finding-field">
                  <span>MALWARE FAMILIES</span>
                  <strong>
                    {otxMalwareFamilies.length > 0
                      ? otxMalwareFamilies.slice(0, 4).join(", ") +
                        (otxMalwareFamilies.length > 4
                          ? ` +${otxMalwareFamilies.length - 4} more`
                          : "")
                      : "Not identified"}
                  </strong>
                </div>

                <div className="finding-field">
                  <span>ADVERSARIES</span>
                  <strong>
                    {otxAdversaries.length > 0
                      ? otxAdversaries.slice(0, 4).join(", ") +
                        (otxAdversaries.length > 4
                          ? ` +${otxAdversaries.length - 4} more`
                          : "")
                      : "Not identified"}
                  </strong>
                </div>

                <div className="finding-field">
                  <span>UNIQUE TAGS</span>
                  <strong>{otxTags.length}</strong>
                </div>
              </div>

              {recentOtxPulses.length > 0 && (
                <div className="source-contribution-list">
                  {recentOtxPulses.map((pulse) => (
                    <span key={`otx-summary-${pulse.id}`}>
                      <ChevronRight size={11} />
                      {pulse.name}
                      {pulse.author ? ` — ${pulse.author}` : ""}
                    </span>
                  ))}

                  {result.otx.pulses.length > recentOtxPulses.length && (
                    <span>
                      <ChevronRight size={11} />
                      +{result.otx.pulses.length - recentOtxPulses.length}{" "}
                      additional Pulse matches consolidated
                    </span>
                  )}
                </div>
              )}

              <div className="finding-assessment">
                <CircleAlert size={16} />
                <div>
                  <strong>Why This Matters</strong>
                  <p>
                    OTX independently associates this IOC with threat
                    reporting. NIGHTWATCH counts OTX as one intelligence
                    source regardless of how many Pulses contain the IOC,
                    preventing dozens of Pulse matches from overwhelming
                    the assessment or inflating source corroboration.
                  </p>
                </div>
              </div>
            </section>
          )}

          {/* THREAT INTELLIGENCE */}

          <section className="research-panel">
            <div className="panel-header">
              <div>
                <h2>
                  <ShieldAlert size={15} />
                  Threat Intelligence
                </h2>

                <p>
                  Source-attributed threat
                  observations returned by
                  connected intelligence
                  providers.
                </p>
              </div>
            </div>

            {result.observations.filter(
              (observation) =>
                observation.source !== "ThreatFox" &&
                observation.source !== "URLhaus",
            ).length === 0 ? (
              <div className="empty-panel">
                <ShieldQuestion
                  size={19}
                />

                <strong>
                  No Threat Observations
                </strong>

                <span>
                  Connected providers
                  returned no current
                  intelligence for this
                  indicator. This does not
                  mean the indicator is
                  benign.
                </span>
              </div>
            ) : (
              <div className="threat-findings">
                {result.observations
                  .filter(
                    (observation) =>
                      observation.source !== "ThreatFox" &&
                      observation.source !== "URLhaus",
                  )
                  .map(
                  (
                    observation,
                    index,
                  ) => (
                    <article
                      className="threat-finding-card"
                      key={`${observation.source}-${index}`}
                    >

                      {/* FINDING HEADER */}

                      <div className="finding-header">
                        <div className="finding-heading">
                          <div className="finding-icon">
                            <ShieldAlert
                              size={18}
                            />
                          </div>

                          <div>
                            <span className="finding-label">
                              THREAT
                              INTELLIGENCE
                            </span>

                            <h3>
                              {observation.description}
                            </h3>
                          </div>
                        </div>

                        <span className="finding-source">
                          {observation.source}
                        </span>
                      </div>

                      {/* FINDING DETAILS */}

                      <div className="finding-grid">

                        <div className="finding-field">
                          <span>
                            Threat Type
                          </span>

                          <strong>
                            {observation.type ||
                              "Unknown"}
                          </strong>
                        </div>

                        <div className="finding-field">
                          <span>
                            Malware Family
                          </span>

                          <strong>
                            {observation.malware ||
                              "Not identified"}
                          </strong>
                        </div>

                        <div className="finding-field">
                          <span>
                            Confidence
                          </span>

                          <strong>
                            {typeof observation
                              .confidence ===
                            "number"
                              ? `${observation.confidence}%`
                              : "Unknown"}
                          </strong>
                        </div>

                        <div className="finding-field">
                          <span>
                            Source
                          </span>

                          <strong>
                            {observation.source}
                          </strong>
                        </div>

                        <div className="finding-field">
                          <span>
                            First Seen
                          </span>

                          <strong>
                            {observation.firstSeen
                              ? new Date(
                                  observation.firstSeen,
                                ).toLocaleString()
                              : "Unknown"}
                          </strong>
                        </div>

                        <div className="finding-field">
                          <span>
                            Last Seen
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

                      {/* TAGS */}

                      {observation.tags &&
                        observation.tags
                          .length > 0 && (
                          <div className="finding-tags">
                            <span className="finding-tags-label">
                              TAGS
                            </span>

                            <div className="finding-tag-list">
                              {observation.tags.map(
                                (
                                  tag,
                                  tagIndex,
                                ) => (
                                  <span
                                    className="finding-tag"
                                    key={`${tag}-${tagIndex}`}
                                  >
                                    {tag}
                                  </span>
                                ),
                              )}
                            </div>
                          </div>
                        )}

                      {/* NIGHTWATCH ASSESSMENT */}

                      <div className="finding-assessment">
                        <ShieldAlert
                          size={16}
                        />

                        <div>
                          <strong>
                            NIGHTWATCH Finding
                          </strong>

                          <p>
                            This indicator has
                            been observed by{" "}
                            {observation.source}
                            {" "}in threat
                            intelligence data
                            and has a malicious
                            association. Review
                            the supporting
                            context before
                            making an
                            operational
                            decision.
                          </p>
                        </div>
                      </div>

                    </article>
                  ),
                )}
              </div>
            )}
          </section>

                {/* RELATIONSHIPS */}

          <section className="research-panel">
            <div className="panel-header">
              <div>
                <h2>
                  <Globe2 size={15} />
                  Relationships
                </h2>

                <p>
                  Infrastructure and
                  indicators related to this
                  research target.
                </p>
              </div>
            </div>

            <div className="relationship-preview">

              {/* PRIMARY TARGET */}

              <div className="graph-node primary-node">
                <Globe2 size={15} />

                <div className="relationship-node-content">
                  <span className="relationship-node-label">
                    RESEARCH TARGET
                  </span>

                  <strong>
                    {result.indicator.value}
                  </strong>
                </div>
              </div>

              {/* DISCOVERED RELATIONSHIPS */}

              {result.relationships.length === 0 ? (
                <div className="graph-empty">
                  No relationships discovered
                </div>
              ) : (
                <div className="relationship-list">
                  {result.relationships.map(
                    (relationship) => (
                      <div
                        className="relationship-row"
                        key={relationship.id}
                      >
                        <div className="relationship-connector">
                          <span className="connector-line" />

                          <span className="connector-label">
                            {relationship.relationship}
                          </span>

                          <span className="connector-arrow">
                            ↓
                          </span>
                        </div>

                        <button
                          type="button"
                          className="relationship-node relationship-node-clickable"
                          onClick={() => {
                            if (
                              relationship.nodeType !==
                              "malware"
                            ) {
                              onPivot(
                                relationship.to,
                              )
                            }
                          }}
                          disabled={
                            relationship.nodeType ===
                            "malware"
                          }
                          title={
                            relationship.nodeType ===
                            "malware"
                              ? `${relationship.to} is a malware family, not a supported IOC pivot`
                              : `Investigate ${relationship.to}`
                          }
                        >
                          <div className="relationship-node-top">
                            <span className="relationship-type">
                              {relationship.nodeType.toUpperCase()}
                            </span>

                            <span className="relationship-source">
                              {relationship.source}
                            </span>
                          </div>

                          <strong>
                            {relationship.to}
                          </strong>
                        </button>
                      </div>
                    ),
                  )}
                </div>
              )}
            </div>
          </section>

        </div>

        {/* RIGHT COLUMN */}

        <aside className="research-side-column">

          {/* SOURCES */}

          <section className="research-panel">
            <div className="panel-header compact">
              <div>
                <h2>
                  <Database size={15} />
                  Evidence Sources
                </h2>

                <p>
                  Provenance and evidence
                  contributed by each provider.
                </p>
              </div>
            </div>

            {result.sources.length ===
            0 ? (
              <div className="empty-source-state">
                <Database size={18} />

                <strong>
                  No providers connected
                </strong>

                <span>
                  Threat intelligence
                  sources will appear here.
                </span>
              </div>
            ) : (
              <div className="source-list">
                {result.sources.map((source) => (
                  <div
                    className="source-row"
                    key={source.name}
                  >
                    <div>
                      <span
                        className={`source-dot source-${source.status}`}
                      />

                      <div>
                        <strong>{source.name}</strong>

                        <span className="source-evidence-summary">
                          {source.evidenceFound
                            ? `${source.evidenceCount} evidence signal${
                                source.evidenceCount === 1 ? "" : "s"
                              }`
                            : source.contribution.length > 0
                              ? "Context collected"
                              : source.status === "no_record"
                                ? "No matching record — not evidence of safety"
                                : "No evidence contributed"}
                        </span>

                        {source.contribution.length > 0 && (
                          <div className="source-contribution-list">
                            {source.contribution.map((item) => (
                              <span key={`${source.name}-${item}`}>
                                <ChevronRight size={11} />
                                {item}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>

                    <span
                      className={`source-status source-status-${source.status}`}
                    >
                      {source.status
                        .replace("_", " ")
                        .toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* OSINT PIVOTS */}

          <section className="research-panel">
            <div className="panel-header compact">
              <div>
                <h2>
                  <ExternalLink
                    size={15}
                  />
                  OSINT Pivots
                </h2>

                <p>
                  External research pivots
                  for supported indicators.
                </p>
              </div>
            </div>

            <div className="empty-source-state">
              <ExternalLink size={18} />

              <strong>
                Pivots not configured
              </strong>

              <span>
                External research links
                will appear here.
              </span>
            </div>
          </section>

          {/* NOTES */}

          <section className="research-panel">
            <div className="panel-header compact">
              <div>
                <h2>
                  <NotebookPen size={15} />
                  Research Notes
                </h2>
              </div>
            </div>

            <textarea
              className="research-notes"
              placeholder="Record analyst observations, questions, and research findings..."
              value={notes}
              onChange={(event) =>
                setNotes(event.target.value)
              }
            />

            <button className="save-note-button">
              Save Note
            </button>
          </section>

        </aside>
      </div>
    </div>
  )
}