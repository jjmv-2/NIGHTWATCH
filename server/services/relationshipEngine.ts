import type {
  IntelligenceRelationship,
  RelationshipNodeType,
} from "../types/intelligence"

import type {
  ThreatFoxResult,
} from "./threatfox"

import type {
  URLhausResult,
} from "./urlhaus"

type BuildRelationshipsInput = {
  indicator: string
  threatFox: ThreatFoxResult
  urlhaus: URLhausResult
  dnsRelationships?:
    IntelligenceRelationship[]
}

function createId(
  source: string,
  relationship: string,
  value: string,
) {
  return [
    source,
    relationship,
    value,
  ]
    .join(":")
    .toLowerCase()
    .replace(
      /[^a-z0-9]+/g,
      "-",
    )
}

function detectNodeType(
  value: string,
): RelationshipNodeType {
  if (
    /^https?:\/\//i.test(value)
  ) {
    return "url"
  }

  if (
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(
      value,
    )
  ) {
    return "ip"
  }

  if (
    /^[a-fA-F0-9]{32}$/.test(value) ||
    /^[a-fA-F0-9]{40}$/.test(value) ||
    /^[a-fA-F0-9]{64}$/.test(value)
  ) {
    return "hash"
  }

  if (value.includes(".")) {
    return "domain"
  }

  return "indicator"
}

export function buildRelationships({
  indicator,
  threatFox,
  urlhaus,
  dnsRelationships = [],
}: BuildRelationshipsInput):
  IntelligenceRelationship[] {
  const relationships:
    IntelligenceRelationship[] = [
      ...dnsRelationships,
    ]

  for (
    const record of
    threatFox.records
  ) {
    const malware =
      record.malware_printable

    if (malware) {
      relationships.push({
        id:
          createId(
            "ThreatFox",
            "associated-with",
            malware,
          ),
        source: "ThreatFox",
        from: indicator,
        to: malware,
        relationship:
          "associated with",
        nodeType: "malware",
      })
    }
  }

  for (
    const record of
    urlhaus.records
  ) {
    if (
      record.url &&
      record.url !== indicator
    ) {
      relationships.push({
        id:
          createId(
            "URLhaus",
            "observed-url",
            record.url,
          ),
        source: "URLhaus",
        from: indicator,
        to: record.url,
        relationship:
          "observed URL",
        nodeType: "url",
      })
    }

    if (
      record.host &&
      record.host !== indicator
    ) {
      relationships.push({
        id:
          createId(
            "URLhaus",
            "host",
            record.host,
          ),
        source: "URLhaus",
        from:
          record.url ||
          indicator,
        to: record.host,
        relationship:
          "hosted by",
        nodeType:
          detectNodeType(
            record.host,
          ),
      })
    }

    for (
      const hash of
      record.payloadHashes ?? []
    ) {
      relationships.push({
        id:
          createId(
            "URLhaus",
            "payload",
            hash,
          ),
        source: "URLhaus",
        from:
          record.url ||
          indicator,
        to: hash,
        relationship:
          "delivers payload",
        nodeType: "hash",
      })
    }
  }

  return Array.from(
    new Map(
      relationships.map(
        (relationship) => [
          relationship.id,
          relationship,
        ],
      ),
    ).values(),
  )
}