export type URLhausStatus =
  | "connected"
  | "no_record"
  | "error"
  | "not_configured"

export type URLhausRecord = {
  url: string

  status?: string | null

  host?: string | null

  dateAdded?: string | null

  threat?: string | null

  tags?: string[]

  reporter?: string | null

  payloadHashes?: string[]
}

export type URLhausResult = {
  status: URLhausStatus

  records: URLhausRecord[]

  error?: string
}

type URLhausExportRecord = {
  id?: string | number

  dateadded?: string

  url?: string

  url_status?: string

  last_online?: string

  threat?: string

  tags?: string[] | string | null

  reporter?: string
}

const URLHAUS_EXPORT_BASE =
  "https://urlhaus-api.abuse.ch/v2/files/exports"

function extractHost(
  value: string,
): string | null {
  try {
    return new URL(value).hostname
  } catch {
    return null
  }
}

function normalizeTags(
  tags: URLhausExportRecord["tags"],
): string[] {
  if (Array.isArray(tags)) {
    return tags
  }

  if (typeof tags === "string") {
    return tags
      .split(",")
      .map((tag) => tag.trim())
      .filter(Boolean)
  }

  return []
}

function matchesIndicator(
  record: URLhausExportRecord,
  indicator: string,
): boolean {
  if (!record.url) {
    return false
  }

  const search =
    indicator.trim().toLowerCase()

  const recordUrl =
    record.url.toLowerCase()

  if (recordUrl === search) {
    return true
  }

  const host =
    extractHost(record.url)
      ?.toLowerCase()

  if (host === search) {
    return true
  }

  return false
}

export async function searchURLhaus(
  indicator: string,
): Promise<URLhausResult> {
  const authKey =
    process.env.URLHAUS_AUTH_KEY

  if (!authKey) {
    console.warn(
      "URLhaus Auth-Key is not configured.",
    )

    return {
      status: "not_configured",
      records: [],
    }
  }

  try {
    const endpoint =
      `${URLHAUS_EXPORT_BASE}/${encodeURIComponent(
        authKey,
      )}/recent.json`

    const response =
      await fetch(endpoint)

    if (!response.ok) {
      console.error(
        `URLhaus HTTP error: ${response.status}`,
      )

      return {
        status: "error",

        records: [],

        error:
          `URLhaus returned HTTP ${response.status}.`,
      }
    }

    const raw =
      await response.json()

    const exportedRecords:
      URLhausExportRecord[] =
        Array.isArray(raw)
          ? raw
          : Array.isArray(raw?.urls)
            ? raw.urls
            : Array.isArray(raw?.data)
              ? raw.data
              : []

    const matches =
      exportedRecords.filter(
        (record) =>
          matchesIndicator(
            record,
            indicator,
          ),
      )

    if (matches.length === 0) {
      return {
        status: "no_record",
        records: [],
      }
    }

    const records:
      URLhausRecord[] =
        matches.map(
          (record) => ({
            url:
              record.url ?? "",

            status:
              record.url_status ??
              null,

            host:
              record.url
                ? extractHost(
                    record.url,
                  )
                : null,

            dateAdded:
              record.dateadded ??
              null,

            threat:
              record.threat ??
              null,

            tags:
              normalizeTags(
                record.tags,
              ),

            reporter:
              record.reporter ??
              null,

            payloadHashes: [],
          }),
        )

    return {
      status: "connected",
      records,
    }
  } catch (error) {
    console.error(
      "URLhaus request failed:",
      error,
    )

    return {
      status: "error",

      records: [],

      error:
        error instanceof Error
          ? error.message
          : "URLhaus request failed.",
    }
  }
}