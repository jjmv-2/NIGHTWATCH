import type {
  IndicatorType,
  SourceStatus,
} from "../types/intelligence"

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

export type OtxResult = {
  status: SourceStatus
  pulses: OtxPulse[]
  pulseCount: number
  error?: string
}

type OtxPulseRaw = {
  id?: string
  name?: string
  description?: string
  created?: string
  modified?: string
  tags?: string[]
  adversary?: string
  malware_families?: string[]
  industries?: string[]
  targeted_countries?: string[]
  references?: string[]
  author_name?: string
}

type OtxGeneralResponse = {
  pulse_info?: {
    count?: number
    pulses?: OtxPulseRaw[]
  }
}

function getEndpoint(
  indicator: string,
  type: IndicatorType,
): string | null {
  const encoded =
    encodeURIComponent(indicator)

  switch (type) {
    case "ip":
      return `/api/v1/indicators/IPv4/${encoded}/general`

    case "domain":
      return `/api/v1/indicators/domain/${encoded}/general`

    case "url":
      return `/api/v1/indicators/url/${encoded}/general`

    case "hash":
      return `/api/v1/indicators/file/${encoded}/general`

    default:
      return null
  }
}

function normalizePulse(
  pulse: OtxPulseRaw,
): OtxPulse {
  return {
    id:
      pulse.id ??
      `otx-${pulse.name ?? "pulse"}`,
    name:
      pulse.name ??
      "Unnamed OTX Pulse",
    description:
      pulse.description ?? null,
    author:
      pulse.author_name ?? null,
    created:
      pulse.created ?? null,
    modified:
      pulse.modified ?? null,
    tags:
      Array.isArray(pulse.tags)
        ? pulse.tags
        : [],
    adversary:
      pulse.adversary ?? null,
    malwareFamilies:
      Array.isArray(
        pulse.malware_families,
      )
        ? pulse.malware_families
        : [],
    industries:
      Array.isArray(
        pulse.industries,
      )
        ? pulse.industries
        : [],
    targetedCountries:
      Array.isArray(
        pulse.targeted_countries,
      )
        ? pulse.targeted_countries
        : [],
    references:
      Array.isArray(
        pulse.references,
      )
        ? pulse.references
        : [],
  }
}

export async function searchOtx(
  indicator: string,
  type: IndicatorType,
): Promise<OtxResult> {
  const apiKey =
    process.env.OTX_API_KEY

  if (!apiKey) {
    return {
      status: "not_configured",
      pulses: [],
      pulseCount: 0,
    }
  }

  const endpoint =
    getEndpoint(indicator, type)

  if (!endpoint) {
    return {
      status: "not_configured",
      pulses: [],
      pulseCount: 0,
    }
  }

  try {
    const response =
      await fetch(
        `https://otx.alienvault.com${endpoint}`,
        {
          headers: {
            Accept:
              "application/json",
            "X-OTX-API-KEY":
              apiKey,
          },
        },
      )

    if (!response.ok) {
      return {
        status: "error",
        pulses: [],
        pulseCount: 0,
        error:
          `OTX returned HTTP ${response.status}.`,
      }
    }

    const data =
      (await response.json()) as
        OtxGeneralResponse

    const rawPulses =
      Array.isArray(
        data.pulse_info?.pulses,
      )
        ? data.pulse_info!.pulses!
        : []

    const pulses =
      rawPulses.map(
        normalizePulse,
      )

    const pulseCount =
      typeof data.pulse_info?.count ===
      "number"
        ? data.pulse_info.count
        : pulses.length

    return {
      status:
        pulseCount > 0
          ? "connected"
          : "no_record",
      pulses,
      pulseCount,
    }
  } catch (error) {
    return {
      status: "error",
      pulses: [],
      pulseCount: 0,
      error:
        error instanceof Error
          ? error.message
          : "OTX request failed.",
    }
  }
}