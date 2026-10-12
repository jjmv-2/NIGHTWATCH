export type ThreatObservation = {
  source: string
  type: string
  description: string
  malware?: string | null
  confidence?: number | null
  firstSeen?: string | null
  lastSeen?: string | null
  tags?: string[]
}

export type IntelligenceRelationship = {
  id: string
  source: string
  from: string
  to: string
  relationship: string
  nodeType:
    | "indicator"
    | "domain"
    | "ip"
    | "url"
    | "hash"
    | "malware"
}

export type EvidenceItem = {
  id: string
  title: string
  description: string
  explanation: string
  source: string
  category:
    | "threat_intelligence"
    | "malware"
    | "activity"
    | "infrastructure"
    | "historical"
    | "context"
  strength:
    | "strong"
    | "moderate"
    | "context"
  verdict:
    | "malicious"
    | "suspicious"
    | "informational"
  details: {
    label: string
    value: string
  }[]
}

export type InvestigationResponse = {
  indicator: {
    value: string
    type:
      | "domain"
      | "ip"
      | "url"
      | "hash"
      | "cve"
      | "unknown"
  }

  assessment: {
    reputation:
      | "malicious"
      | "suspicious"
      | "unknown"
      | "benign"
    confidence:
      | "high"
      | "medium"
      | "low"
      | "unknown"
    summary: string
    evidenceCount: number
    maliciousEvidenceCount: number
    corroboratingSources: number
  }

  evidence: EvidenceItem[]

  infrastructure: {
    ips: string[]
    domains: string[]
    asns: string[]
    providers: string[]
    countries: string[]
    dns: {
      a: string[]
      aaaa: string[]
      mx: {
        exchange: string
        priority: number
      }[]
      ns: string[]
      cname: string[]
      reverse: string[]
    }
    rdap: {
      ip: string
      name: string | null
      handle: string | null
      startAddress: string | null
      endAddress: string | null
      cidrs: string[]
      organization: string | null
      country: string | null
      registry: string | null
      status: string[]
      registrationDate: string | null
      lastChangedDate: string | null
    }[]
    bgp: {
      ip: string
      prefix: string | null
      asns: number[]
      primaryAsn: number | null
      asName: string | null
      asHolder: string | null
    }[]
  }

  malware: string[]
  otx: {
    pulseCount: number
    pulses: {
      id: string
      name: string
      description: string | null
      author: string | null
      created: string | null
      modified: string | null
      tags: string[]
      adversary: string | null
      malwareFamilies: string[]
      industries: string[]
      targetedCountries: string[]
      references: string[]
    }[]
  }
  observations:
    ThreatObservation[]
  relationships:
    IntelligenceRelationship[]

  sources: {
    name: string
    status:
      | "connected"
      | "no_record"
      | "error"
      | "not_configured"
    evidenceFound: boolean
    evidenceCount: number
    contribution: string[]
  }[]

  investigatedAt: string
}

export async function investigateIndicator(
  indicator: string,
): Promise<InvestigationResponse> {
  const response =
    await fetch(
      "/api/investigate",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body:
          JSON.stringify({
            indicator,
          }),
      },
    )

  const data =
    await response.json()

  if (!response.ok) {
    throw new Error(
      data.error ||
        "Investigation failed.",
    )
  }

  return data as InvestigationResponse
}