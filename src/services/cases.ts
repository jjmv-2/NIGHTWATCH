import type {
  InvestigationTrailItem,
} from "../types/app"

import type {
  InvestigationResponse,
  IntelligenceRelationship,
  ThreatObservation,
} from "./intelligence"

export type CaseStatus =
  | "active"
  | "closed"

export type CreatedCase = {
  id: string
  caseNumber: string
  title: string
  status: CaseStatus
  createdAt: string
}

export type ResearchCaseSummary = {
  id: string
  caseNumber: string
  title: string
  status: CaseStatus
  originalIndicator: string
  originalIndicatorType:
    InvestigationResponse["indicator"]["type"]
  createdAt: string
  updatedAt: string
}

export type ResearchCase = {
  id: string
  caseNumber: string
  title: string
  status: CaseStatus

  originalIndicator: string

  originalIndicatorType:
    InvestigationResponse["indicator"]["type"]

  notes: string

  createdAt: string
  updatedAt: string

  indicators:
    InvestigationTrailItem[]

  observations:
    ThreatObservation[]

  relationships:
    IntelligenceRelationship[]

  sources:
    InvestigationResponse["sources"]
}

type CreateCaseInput = {
  investigation:
    InvestigationResponse

  trail:
    InvestigationTrailItem[]

  notes?: string
}

export async function createCase({
  investigation,
  trail,
  notes = "",
}: CreateCaseInput): Promise<CreatedCase> {
  const response =
    await fetch(
      "/api/cases",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify({
          indicator:
            investigation.indicator,

          trail,

          observations:
            investigation.observations,

          relationships:
            investigation.relationships,

          sources:
            investigation.sources,

          notes,
        }),
      },
    )

  const data =
    await response.json()

  if (!response.ok) {
    throw new Error(
      data.error ||
        "Failed to create case.",
    )
  }

  return data as CreatedCase
}

export async function getCases():
Promise<ResearchCaseSummary[]> {
  const response =
    await fetch("/api/cases")

  const data =
    await response.json()

  if (!response.ok) {
    throw new Error(
      data.error ||
        "Failed to load cases.",
    )
  }

  return data as ResearchCaseSummary[]
}

export async function getCase(
  caseId: string,
): Promise<ResearchCase> {
  const response =
    await fetch(
      `/api/cases/${encodeURIComponent(
        caseId,
      )}`,
    )

  const data =
    await response.json()

  if (!response.ok) {
    throw new Error(
      data.error ||
        "Failed to load case.",
    )
  }

  return data as ResearchCase
}

export async function updateCase(
  caseId: string,
  updates: {
    title?: string
    notes?: string
    status?: CaseStatus
  },
) {
  const response =
    await fetch(
      `/api/cases/${encodeURIComponent(
        caseId,
      )}`,
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body:
          JSON.stringify(updates),
      },
    )

  const data =
    await response.json()

  if (!response.ok) {
    throw new Error(
      data.error ||
        "Failed to update case.",
    )
  }

  return data as {
    id: string
    title: string
    notes: string
    status: CaseStatus
    updatedAt: string
  }
}

export async function appendInvestigationToCase(
  caseId: string,
  investigation:
    InvestigationResponse,
  trail:
    InvestigationTrailItem[],
) {
  const response =
    await fetch(
      `/api/cases/${encodeURIComponent(
        caseId,
      )}/intelligence`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify({
          indicator:
            investigation.indicator,

          trail,

          observations:
            investigation.observations,

          relationships:
            investigation.relationships,

          sources:
            investigation.sources,
        }),
      },
    )

  const data =
    await response.json()

  if (!response.ok) {
    throw new Error(
      data.error ||
        "Failed to add intelligence to case.",
    )
  }

  return data as {
    id: string
    updatedAt: string
  }
}

export async function deleteCase(
  caseId: string,
) {
  const response =
    await fetch(
      `/api/cases/${encodeURIComponent(
        caseId,
      )}`,
      {
        method: "DELETE",
      },
    )

  if (!response.ok) {
    let message =
      "Failed to delete case."

    try {
      const data =
        await response.json()

      message =
        data.error || message
    } catch {
      // No response body.
    }

    throw new Error(message)
  }
}