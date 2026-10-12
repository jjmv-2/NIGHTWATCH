import {
  promises as dns,
} from "node:dns"

import type {
  DnsInfrastructure,
  IndicatorType,
  IntelligenceRelationship,
} from "../types/intelligence"

type DnsEnrichmentResult = {
  dns: DnsInfrastructure
  ips: string[]
  domains: string[]
  relationships:
    IntelligenceRelationship[]
}

function unique(
  values: string[],
) {
  return Array.from(
    new Set(
      values.filter(Boolean),
    ),
  )
}

function relationshipId(
  relationship: string,
  value: string,
) {
  return `dns-${relationship}-${value}`
    .toLowerCase()
    .replace(
      /[^a-z0-9]+/g,
      "-",
    )
}

async function safeResolve4(
  host: string,
) {
  try {
    return await dns.resolve4(host)
  } catch {
    return []
  }
}

async function safeResolve6(
  host: string,
) {
  try {
    return await dns.resolve6(host)
  } catch {
    return []
  }
}

async function safeResolveMx(
  host: string,
) {
  try {
    return await dns.resolveMx(host)
  } catch {
    return []
  }
}

async function safeResolveNs(
  host: string,
) {
  try {
    return await dns.resolveNs(host)
  } catch {
    return []
  }
}

async function safeResolveCname(
  host: string,
) {
  try {
    return await dns.resolveCname(host)
  } catch {
    return []
  }
}

async function safeReverse(
  ip: string,
) {
  try {
    return await dns.reverse(ip)
  } catch {
    return []
  }
}

function hostFromIndicator(
  indicator: string,
  type: IndicatorType,
): string | null {
  if (type === "domain") {
    return indicator
  }

  if (type === "url") {
    try {
      return new URL(
        indicator,
      ).hostname
    } catch {
      return null
    }
  }

  return null
}

export async function enrichDns(
  indicator: string,
  type: IndicatorType,
): Promise<DnsEnrichmentResult> {
  const empty: DnsInfrastructure = {
    a: [],
    aaaa: [],
    mx: [],
    ns: [],
    cname: [],
    reverse: [],
  }

  if (type === "ip") {
    const reverse =
      await safeReverse(
        indicator,
      )

    const domains =
      unique(reverse)

    return {
      dns: {
        ...empty,
        reverse: domains,
      },
      ips: [],
      domains,
      relationships:
        domains.map(
          (domain) => ({
            id:
              relationshipId(
                "reverse-dns",
                domain,
              ),
            source: "DNS",
            from: indicator,
            to: domain,
            relationship:
              "reverse DNS",
            nodeType: "domain",
          }),
        ),
    }
  }

  const host =
    hostFromIndicator(
      indicator,
      type,
    )

  if (!host) {
    return {
      dns: empty,
      ips: [],
      domains: [],
      relationships: [],
    }
  }

  const [
    a,
    aaaa,
    mx,
    ns,
    cname,
  ] = await Promise.all([
    safeResolve4(host),
    safeResolve6(host),
    safeResolveMx(host),
    safeResolveNs(host),
    safeResolveCname(host),
  ])

  const ips =
    unique([
      ...a,
      ...aaaa,
    ])

  const relatedDomains =
    unique([
      ...ns,
      ...cname,
      ...mx.map(
        (record) =>
          record.exchange,
      ),
    ]).filter(
      (domain) =>
        domain !== host,
    )

  const relationships:
    IntelligenceRelationship[] = [
      ...ips.map(
        (ip) => ({
          id:
            relationshipId(
              "resolves-to",
              ip,
            ),
          source: "DNS",
          from: host,
          to: ip,
          relationship:
            "resolves to",
          nodeType:
            "ip" as const,
        }),
      ),
      ...cname.map(
        (domain) => ({
          id:
            relationshipId(
              "cname",
              domain,
            ),
          source: "DNS",
          from: host,
          to: domain,
          relationship:
            "CNAME",
          nodeType:
            "domain" as const,
        }),
      ),
    ]

  return {
    dns: {
      a: unique(a),
      aaaa: unique(aaaa),
      mx: mx
        .map((record) => ({
          exchange:
            record.exchange,
          priority:
            record.priority,
        }))
        .sort(
          (left, right) =>
            left.priority -
            right.priority,
        ),
      ns: unique(ns),
      cname: unique(cname),
      reverse: [],
    },
    ips,
    domains:
      relatedDomains,
    relationships,
  }
}