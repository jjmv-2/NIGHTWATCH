export type IndicatorType =
  | "domain"
  | "ip"
  | "url"
  | "hash"
  | "cve"
  | "unknown"

export type InvestigateRequest = {
  indicator: string
}

export type SourceStatus =
  | "connected"
  | "no_record"
  | "error"
  | "not_configured"

export type IntelligenceSource = {
  name: string
  status: SourceStatus
  evidenceFound: boolean
  evidenceCount: number
  contribution: string[]
}

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

export type RelationshipNodeType =
  | "indicator"
  | "domain"
  | "ip"
  | "url"
  | "hash"
  | "malware"

export type IntelligenceRelationship = {
  id: string
  source: string
  from: string
  to: string
  relationship: string
  nodeType: RelationshipNodeType
}

export type EvidenceCategory =
  | "threat_intelligence"
  | "malware"
  | "activity"
  | "infrastructure"
  | "historical"
  | "context"

export type EvidenceStrength =
  | "strong"
  | "moderate"
  | "context"

export type EvidenceVerdict =
  | "malicious"
  | "suspicious"
  | "informational"

export type EvidenceDetail = {
  label: string
  value: string
}

export type EvidenceItem = {
  id: string
  title: string
  description: string
  explanation: string
  source: string
  category: EvidenceCategory
  strength: EvidenceStrength
  verdict: EvidenceVerdict
  details: EvidenceDetail[]
}

export type DnsMxRecord = {
  exchange: string
  priority: number
}

export type DnsInfrastructure = {
  a: string[]
  aaaa: string[]
  mx: DnsMxRecord[]
  ns: string[]
  cname: string[]
  reverse: string[]
}

export type RdapNetworkRecord = {
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
}

export type OtxPulse = {
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
}

export type BgpRouteRecord = {
  ip: string
  prefix: string | null
  asns: number[]
  primaryAsn: number | null
  asName: string | null
  asHolder: string | null
}

export type InvestigationResult = {
  indicator: {
    value: string
    type: IndicatorType
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
    dns: DnsInfrastructure
    rdap: RdapNetworkRecord[]
    bgp: BgpRouteRecord[]
  }

  malware: string[]
  otx: {
    pulseCount: number
    pulses: OtxPulse[]
  }
  observations: ThreatObservation[]
  relationships: IntelligenceRelationship[]
  sources: IntelligenceSource[]
  investigatedAt: string
}