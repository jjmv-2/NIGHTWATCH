import type {
  EvidenceItem,
  InvestigationResult,
} from "../types/intelligence"

import type {
  ThreatFoxResult,
} from "./threatfox"

import type {
  URLhausResult,
} from "./urlhaus"

import type {
  OtxResult,
} from "./otx"

type BuildEvidenceInput = {
  threatFox: ThreatFoxResult
  urlhaus: URLhausResult
  otx: OtxResult
}

function evidenceId(
  source: string,
  kind: string,
  index: number,
) {
  return `${source}-${kind}-${index}`
    .toLowerCase()
    .replace(
      /[^a-z0-9]+/g,
      "-",
    )
}

export function buildEvidence({
  threatFox,
  urlhaus,
  otx,
}: BuildEvidenceInput):
  EvidenceItem[] {
  const evidence:
    EvidenceItem[] = []

  if (threatFox.records.length > 0) {
    const threatTypes = Array.from(
      new Set(
        threatFox.records
          .map(
            (record) =>
              record.threat_type ??
              record.ioc_type,
          )
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

    const malwareFamilies = Array.from(
      new Set(
        threatFox.records
          .map(
            (record) =>
              record.malware_printable,
          )
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

    const reporters = Array.from(
      new Set(
        threatFox.records
          .map(
            (record) =>
              record.reporter,
          )
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

    const confidenceValues =
      threatFox.records
        .map(
          (record) =>
            record.confidence_level,
        )
        .filter(
          (value): value is number =>
            typeof value === "number",
        )

    const highestConfidence =
      confidenceValues.length > 0
        ? Math.max(
            ...confidenceValues,
          )
        : null

    evidence.push({
      id: "threatfox-summary",
      title:
        "ThreatFox IOC Intelligence",
      description:
        `ThreatFox returned ${threatFox.records.length} matching IOC record${
          threatFox.records.length === 1 ? "" : "s"
        } for this indicator.`,
      explanation:
        "NIGHTWATCH consolidates ThreatFox records into one strong provider-level evidence signal. Record count, malware, activity classification, reporter, and confidence remain visible without counting repeated records from the same provider as independent corroboration.",
      source: "ThreatFox",
      category:
        "threat_intelligence",
      strength: "strong",
      verdict: "malicious",
      details: [
        {
          label: "IOC Records",
          value:
            String(
              threatFox.records.length,
            ),
        },
        ...(threatTypes.length > 0
          ? [
              {
                label: "Threat Types",
                value:
                  threatTypes
                    .slice(0, 4)
                    .join(", ") +
                  (threatTypes.length > 4
                    ? ` +${threatTypes.length - 4} more`
                    : ""),
              },
            ]
          : []),
        ...(malwareFamilies.length > 0
          ? [
              {
                label: "Malware Families",
                value:
                  malwareFamilies
                    .slice(0, 4)
                    .join(", ") +
                  (malwareFamilies.length > 4
                    ? ` +${malwareFamilies.length - 4} more`
                    : ""),
              },
            ]
          : []),
        ...(highestConfidence !== null
          ? [
              {
                label: "Highest Confidence",
                value:
                  `${highestConfidence}%`,
              },
            ]
          : []),
        ...(reporters.length > 0
          ? [
              {
                label: "Reporters",
                value:
                  reporters
                    .slice(0, 3)
                    .join(", ") +
                  (reporters.length > 3
                    ? ` +${reporters.length - 3} more`
                    : ""),
              },
            ]
          : []),
      ],
    })
  }

  if (urlhaus.records.length > 0) {
    const threats = Array.from(
      new Set(
        urlhaus.records
          .map(
            (record) =>
              record.threat,
          )
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

    const statuses = Array.from(
      new Set(
        urlhaus.records
          .map(
            (record) =>
              record.status,
          )
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

    const payloadHashes = Array.from(
      new Set(
        urlhaus.records.flatMap(
          (record) =>
            record.payloadHashes ?? [],
        ),
      ),
    )

    const reporters = Array.from(
      new Set(
        urlhaus.records
          .map(
            (record) =>
              record.reporter,
          )
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

    evidence.push({
      id: "urlhaus-summary",
      title:
        "URLhaus Malware Distribution Intelligence",
      description:
        `URLhaus returned ${urlhaus.records.length} matching malware-distribution record${
          urlhaus.records.length === 1 ? "" : "s"
        } for this indicator.`,
      explanation:
        "NIGHTWATCH consolidates URLhaus matches into one strong provider-level evidence signal. The underlying URL, threat, payload, status, and reporting context remain available without flooding the assessment with repeated records from the same source.",
      source: "URLhaus",
      category:
        "threat_intelligence",
      strength: "strong",
      verdict: "malicious",
      details: [
        {
          label: "URL Records",
          value:
            String(
              urlhaus.records.length,
            ),
        },
        ...(threats.length > 0
          ? [
              {
                label: "Threat Types",
                value:
                  threats
                    .slice(0, 4)
                    .join(", ") +
                  (threats.length > 4
                    ? ` +${threats.length - 4} more`
                    : ""),
              },
            ]
          : []),
        ...(statuses.length > 0
          ? [
              {
                label: "Statuses",
                value:
                  statuses.join(", "),
              },
            ]
          : []),
        ...(payloadHashes.length > 0
          ? [
              {
                label: "Payload Hashes",
                value:
                  `${payloadHashes.length} unique payload${
                    payloadHashes.length === 1 ? "" : "s"
                  }`,
              },
            ]
          : []),
        ...(reporters.length > 0
          ? [
              {
                label: "Reporters",
                value:
                  reporters
                    .slice(0, 3)
                    .join(", ") +
                  (reporters.length > 3
                    ? ` +${reporters.length - 3} more`
                    : ""),
              },
            ]
          : []),
      ],
    })
  }

  if (otx.pulses.length > 0) {
    const malwareFamilies = Array.from(
      new Set(
        otx.pulses.flatMap(
          (pulse) => pulse.malwareFamilies,
        ),
      ),
    )

    const adversaries = Array.from(
      new Set(
        otx.pulses
          .map((pulse) => pulse.adversary)
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

    const authors = Array.from(
      new Set(
        otx.pulses
          .map((pulse) => pulse.author)
          .filter(
            (value): value is string =>
              Boolean(value),
          ),
      ),
    )

    evidence.push({
      id: "otx-pulse-summary",
      title: "OTX Pulse Corroboration",
      description:
        `OTX contains ${otx.pulseCount} Pulse association${
          otx.pulseCount === 1 ? "" : "s"
        } for this indicator.`,
      explanation:
        "NIGHTWATCH consolidates OTX Pulse matches into one evidence signal. The Pulse count shows how broadly the IOC appears in OTX reporting without treating every Pulse as a separate independent source.",
      source: "OTX",
      category: "threat_intelligence",
      strength: "moderate",
      verdict: "malicious",
      details: [
        {
          label: "Pulse Matches",
          value: String(otx.pulseCount),
        },
        ...(authors.length > 0
          ? [
              {
                label: "Reporting Authors",
                value:
                  authors.slice(0, 4).join(", ") +
                  (authors.length > 4
                    ? ` +${authors.length - 4} more`
                    : ""),
              },
            ]
          : []),
        ...(malwareFamilies.length > 0
          ? [
              {
                label: "Malware Families",
                value:
                  malwareFamilies.slice(0, 4).join(", ") +
                  (malwareFamilies.length > 4
                    ? ` +${malwareFamilies.length - 4} more`
                    : ""),
              },
            ]
          : []),
        ...(adversaries.length > 0
          ? [
              {
                label: "Adversaries",
                value:
                  adversaries.slice(0, 4).join(", ") +
                  (adversaries.length > 4
                    ? ` +${adversaries.length - 4} more`
                    : ""),
              },
            ]
          : []),
      ],
    })
  }

  return evidence
}

export function buildAssessment(
  evidence: EvidenceItem[],
): InvestigationResult[
  "assessment"
] {
  const maliciousEvidence =
    evidence.filter(
      (item) =>
        item.verdict ===
        "malicious",
    )

  const strongEvidence =
    maliciousEvidence.filter(
      (item) =>
        item.strength ===
        "strong",
    )

  const sourceCount =
    new Set(
      maliciousEvidence.map(
        (item) =>
          item.source,
      ),
    ).size

  let reputation:
    InvestigationResult[
      "assessment"
    ]["reputation"] =
      "unknown"

  if (
    maliciousEvidence.length > 0
  ) {
    reputation = "malicious"
  } else if (
    evidence.some(
      (item) =>
        item.verdict ===
        "suspicious",
    )
  ) {
    reputation = "suspicious"
  }

  let confidence:
    InvestigationResult[
      "assessment"
    ]["confidence"] =
      "unknown"

  if (
    strongEvidence.length > 0
  ) {
    confidence =
      sourceCount >= 2
        ? "high"
        : "medium"
  } else if (
    maliciousEvidence.length > 0
  ) {
    confidence = "low"
  }

  const summary =
    reputation === "malicious"
      ? `NIGHTWATCH found ${maliciousEvidence.length} malicious evidence signal${maliciousEvidence.length === 1 ? "" : "s"} across ${sourceCount} intelligence source${sourceCount === 1 ? "" : "s"}. The classification is based on source-attributed threat-intelligence evidence.`
      : "NIGHTWATCH did not receive direct malicious evidence from the currently connected intelligence providers. This does not establish that the indicator is benign."

  return {
    reputation,
    confidence,
    summary,
    evidenceCount:
      evidence.length,
    maliciousEvidenceCount:
      maliciousEvidence.length,
    corroboratingSources:
      sourceCount,
  }
}