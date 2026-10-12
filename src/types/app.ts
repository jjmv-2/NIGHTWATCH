export type Page =
  | "home"
  | "investigate"
  | "cases"
  | "indicators"
  | "monitoring"
  | "reports"
  | "integrations"
  | "settings"

export type IndicatorType =
  | "domain"
  | "ip"
  | "url"
  | "hash"
  | "cve"
  | "unknown"

export type ResearchItem = {
  id: string
  value: string
  type: IndicatorType
  investigatedAt: string
}
export type InvestigationTrailItem = {
  value: string
  type: IndicatorType
}