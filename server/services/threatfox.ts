export type ThreatFoxIOC = {
  id: string

  ioc: string

  ioc_type: string

  ioc_type_desc?: string | null

  threat_type?: string | null

  threat_type_desc?: string | null

  malware?: string | null

  malware_printable?: string | null

  malware_alias?: string | null

  confidence_level?: number | null

  first_seen?: string | null

  last_seen?: string | null

  reporter?: string | null

  reference?: string | null

  tags?: string[] | null
}

type ThreatFoxResponse = {
  query_status: string

  data?:
    | ThreatFoxIOC[]
    | null
}

export type ThreatFoxResult = {
  status:
    | "connected"
    | "no_record"
    | "error"
    | "not_configured"

  records: ThreatFoxIOC[]

  error?: string
}

const THREATFOX_URL =
  "https://threatfox-api.abuse.ch/api/v1/"

export async function searchThreatFox(
  indicator: string,
): Promise<ThreatFoxResult> {
  /*
   * Keep the API key on the backend.
   * Never expose this through React.
   */

  const authKey =
    process.env.THREATFOX_AUTH_KEY

  if (!authKey) {
    console.warn(
      "ThreatFox Auth-Key is not configured.",
    )

    return {
      status: "not_configured",
      records: [],
    }
  }

  try {
    const response =
      await fetch(
        THREATFOX_URL,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",

            "Auth-Key":
              authKey,
          },

          body:
            JSON.stringify({
              query:
                "search_ioc",

              search_term:
                indicator,

              exact_match:
                true,
            }),
        },
      )

    /*
     * HTTP-level failure
     */

    if (!response.ok) {
  const responseText =
    await response.text()

  console.error(
    `ThreatFox HTTP error: ${response.status}`,
  )

  console.error(
    "ThreatFox response:",
    responseText,
  )

  return {
    status: "error",
    records: [],

    error:
      `ThreatFox returned HTTP ${response.status}.`,
  }
}

    const data =
      (await response.json()) as
        ThreatFoxResponse

    /*
     * ThreatFox was successfully
     * queried but has no record.
     *
     * IMPORTANT:
     * NO_RECORD does NOT mean benign.
     */

    if (
      data.query_status ===
        "no_result" ||
      !Array.isArray(
        data.data,
      ) ||
      data.data.length === 0
    ) {
      return {
        status: "no_record",
        records: [],
      }
    }

    /*
     * ThreatFox returned IOC
     * intelligence.
     */

    return {
      status: "connected",
      records: data.data,
    }
  } catch (error) {
    console.error(
      "ThreatFox request failed:",
      error,
    )

    return {
      status: "error",
      records: [],

      error:
        error instanceof Error
          ? error.message
          : "ThreatFox request failed.",
    }
  }
}