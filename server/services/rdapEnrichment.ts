import type {
  RdapNetworkRecord,
  SourceStatus,
} from "../types/intelligence"

type RdapEntity = {
  handle?: string
  roles?: string[]
  vcardArray?: [
    string,
    Array<
      [
        string,
        Record<string, unknown>,
        string,
        unknown,
      ]
    >,
  ]
}

type RdapEvent = {
  eventAction?: string
  eventDate?: string
}

type RdapCidr = {
  v4prefix?: string
  v6prefix?: string
  length?: number
}

type RdapResponse = {
  handle?: string
  name?: string
  startAddress?: string
  endAddress?: string
  country?: string
  port43?: string
  status?: string[]
  entities?: RdapEntity[]
  events?: RdapEvent[]
  cidr0_cidrs?: RdapCidr[]
}

export type RdapEnrichmentResult = {
  status: SourceStatus
  records: RdapNetworkRecord[]
  error?: string
}

const RDAP_BASE =
  "https://rdap.org/ip"

function getVcardName(
  entity: RdapEntity,
): string | null {
  const properties =
    entity.vcardArray?.[1]

  if (!Array.isArray(properties)) {
    return null
  }

  const preferred =
    ["fn", "org"]

  for (const key of preferred) {
    const entry =
      properties.find(
        (property) =>
          property[0] === key,
      )

    if (
      entry &&
      typeof entry[3] === "string" &&
      entry[3].trim()
    ) {
      return entry[3].trim()
    }
  }

  return null
}

function getOrganization(
  entities:
    | RdapEntity[]
    | undefined,
): string | null {
  if (!entities) {
    return null
  }

  const preferred =
    entities.find(
      (entity) =>
        entity.roles?.some(
          (role) =>
            role === "registrant" ||
            role === "administrative" ||
            role === "technical",
        ),
    )

  return (
    getVcardName(
      preferred ?? entities[0] ?? {},
    ) ?? null
  )
}

function getEventDate(
  events:
    | RdapEvent[]
    | undefined,
  actions: string[],
): string | null {
  const event =
    events?.find(
      (candidate) =>
        candidate.eventAction &&
        actions.includes(
          candidate.eventAction,
        ),
    )

  return event?.eventDate ?? null
}

function getRegistry(
  data: RdapResponse,
): string | null {
  if (data.port43) {
    return data.port43
      .replace(/^whois\./i, "")
      .split(".")[0]
      ?.toUpperCase() ?? null
  }

  return null
}

function getCidrs(
  data: RdapResponse,
): string[] {
  return (
    data.cidr0_cidrs ?? []
  )
    .map((cidr) => {
      const prefix =
        cidr.v4prefix ??
        cidr.v6prefix

      if (
        !prefix ||
        typeof cidr.length !== "number"
      ) {
        return null
      }

      return `${prefix}/${cidr.length}`
    })
    .filter(
      (value): value is string =>
        Boolean(value),
    )
}

export async function enrichRdap(
  ips: string[],
): Promise<RdapEnrichmentResult> {
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
      targets.map(async (ip) => {
        const response =
          await fetch(
            `${RDAP_BASE}/${encodeURIComponent(ip)}`,
            {
              headers: {
                Accept:
                  "application/rdap+json, application/json",
              },
            },
          )

        if (response.status === 404) {
          return null
        }

        if (!response.ok) {
          throw new Error(
            `RDAP HTTP ${response.status} for ${ip}`,
          )
        }

        const data =
          (await response.json()) as
            RdapResponse

        const record:
          RdapNetworkRecord = {
            ip,
            name:
              data.name ?? null,
            handle:
              data.handle ?? null,
            startAddress:
              data.startAddress ??
              null,
            endAddress:
              data.endAddress ??
              null,
            cidrs:
              getCidrs(data),
            organization:
              getOrganization(
                data.entities,
              ),
            country:
              data.country ?? null,
            registry:
              getRegistry(data),
            status:
              data.status ?? [],
            registrationDate:
              getEventDate(
                data.events,
                [
                  "registration",
                  "allocated",
                  "assigned",
                ],
              ),
            lastChangedDate:
              getEventDate(
                data.events,
                [
                  "last changed",
                  "last update of RDAP database",
                ],
              ),
          }

        return record
      }),
    )

  const records =
    settled
      .filter(
        (
          result,
        ): result is PromiseFulfilledResult<
          RdapNetworkRecord | null
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
        ): record is RdapNetworkRecord =>
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
        "RDAP enrichment failed for all discovered IP addresses.",
    }
  }

  return {
    status: "no_record",
    records: [],
  }
}