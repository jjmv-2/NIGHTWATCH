import type {
  SourceStatus,
} from "../types/intelligence"

export type BgpRouteRecord = {
  ip: string
  prefix: string | null
  asns: number[]
  primaryAsn: number | null
  asName: string | null
  asHolder: string | null
}

export type BgpEnrichmentResult = {
  status: SourceStatus
  records: BgpRouteRecord[]
  error?: string
}

type NetworkInfoResponse = {
  data?: {
    prefix?: string
    asns?: number[]
  }
}

type AsOverviewResponse = {
  data?: {
    holder?: string
    resource?: string
  }
}

const RIPESTAT_BASE =
  "https://stat.ripe.net/data"

async function getAsHolder(
  asn: number,
): Promise<string | null> {
  try {
    const response =
      await fetch(
        `${RIPESTAT_BASE}/as-overview/data.json?resource=AS${asn}`,
        {
          headers: {
            Accept: "application/json",
          },
        },
      )

    if (!response.ok) {
      return null
    }

    const data =
      (await response.json()) as
        AsOverviewResponse

    return (
      data.data?.holder ??
      null
    )
  } catch {
    return null
  }
}

export async function enrichBgp(
  ips: string[],
): Promise<BgpEnrichmentResult> {
  const targets =
    Array.from(
      new Set(ips),
    ).slice(0, 12)

  if (targets.length === 0) {
    return {
      status: "no_record",
      records: [],
    }
  }

  const settled =
    await Promise.allSettled(
      targets.map(
        async (
          ip,
        ): Promise<BgpRouteRecord | null> => {
          const response =
            await fetch(
              `${RIPESTAT_BASE}/network-info/data.json?resource=${encodeURIComponent(ip)}`,
              {
                headers: {
                  Accept:
                    "application/json",
                },
              },
            )

          if (!response.ok) {
            throw new Error(
              `RIPEstat HTTP ${response.status} for ${ip}`,
            )
          }

          const data =
            (await response.json()) as
              NetworkInfoResponse

          const prefix =
            data.data?.prefix ??
            null

          const asns =
            Array.isArray(
              data.data?.asns,
            )
              ? data.data!.asns!
                  .filter(
                    (asn) =>
                      Number.isInteger(
                        asn,
                      ),
                  )
              : []

          if (
            !prefix &&
            asns.length === 0
          ) {
            return null
          }

          const primaryAsn =
            asns[0] ?? null

          const holder =
            primaryAsn
              ? await getAsHolder(
                  primaryAsn,
                )
              : null

          return {
            ip,
            prefix,
            asns,
            primaryAsn,
            asName: holder,
            asHolder: holder,
          }
        },
      ),
    )

  const records =
    settled
      .filter(
        (
          result,
        ): result is PromiseFulfilledResult<
          BgpRouteRecord | null
        > =>
          result.status ===
          "fulfilled",
      )
      .map(
        (result) =>
          result.value,
      )
      .filter(
        (
          record,
        ): record is BgpRouteRecord =>
          record !== null,
      )

  if (records.length > 0) {
    return {
      status: "connected",
      records,
    }
  }

  const failures =
    settled.filter(
      (result) =>
        result.status ===
        "rejected",
    )

  if (
    failures.length ===
    settled.length
  ) {
    return {
      status: "error",
      records: [],
      error:
        "BGP enrichment failed for all discovered IP addresses.",
    }
  }

  return {
    status: "no_record",
    records: [],
  }
}