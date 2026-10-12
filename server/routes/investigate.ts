import { Router } from "express"

import {
  searchThreatFox,
  type ThreatFoxResult,
} from "../services/threatfox"

import {
  searchURLhaus,
  type URLhausResult,
} from "../services/urlhaus"

import {
  buildRelationships,
} from "../services/relationshipEngine"

import {
  enrichDns,
} from "../services/dnsEnrichment"

import {
  buildAssessment,
  buildEvidence,
} from "../services/evidenceEngine"

import {
  enrichRdap,
} from "../services/rdapEnrichment"

import {
  enrichBgp,
} from "../services/bgpEnrichment"

import {
  searchOtx,
} from "../services/otx"

import {
  detectIndicatorType,
} from "../utils/detectIndicator"

import type {
  IntelligenceSource,
  InvestigationResult,
  InvestigateRequest,
  ThreatObservation,
} from "../types/intelligence"

const router = Router()

function unique(
  values: string[],
) {
  return Array.from(
    new Set(
      values.filter(Boolean),
    ),
  )
}

router.post(
  "/",
  async (req, res) => {
    const body =
      req.body as Partial<InvestigateRequest>

    const indicator =
      body.indicator?.trim()

    if (!indicator) {
      return res.status(400).json({
        error:
          "Indicator is required.",
      })
    }

    const type =
      detectIndicatorType(
        indicator,
      )

    if (type === "unknown") {
      return res.status(400).json({
        error:
          "Unsupported or invalid indicator.",
      })
    }

    let threatFox:
      ThreatFoxResult

    let urlhaus:
      URLhausResult

    const otxPromise =
      searchOtx(
        indicator,
        type,
      )

    const dnsPromise =
      enrichDns(
        indicator,
        type,
      )

    if (type === "cve") {
      threatFox = {
        status:
          "not_configured",
        records: [],
      }

      urlhaus = {
        status:
          "not_configured",
        records: [],
      }
    } else {
      ;[
        threatFox,
        urlhaus,
      ] =
        await Promise.all([
          searchThreatFox(
            indicator,
          ),
          searchURLhaus(
            indicator,
          ),
        ])
    }

    const [
      dnsResult,
      otxResult,
    ] =
      await Promise.all([
        dnsPromise,
        otxPromise,
      ])

    const malware =
      unique(
        threatFox.records
          .map(
            (record) =>
              record
                .malware_printable ??
              "",
          ),
      )

    const threatFoxObservations:
      ThreatObservation[] =
        threatFox.records.map(
          (record) => ({
            source:
              "ThreatFox",
            type:
              record.threat_type ??
              record.ioc_type ??
              "IOC",
            description:
              record
                .threat_type_desc ??
              record
                .ioc_type_desc ??
              "ThreatFox IOC observation",
            malware:
              record
                .malware_printable ??
              null,
            confidence:
              record
                .confidence_level ??
              null,
            firstSeen:
              record.first_seen ??
              null,
            lastSeen:
              record.last_seen ??
              null,
            tags:
              record.tags ?? [],
          }),
        )

    const urlhausObservations:
      ThreatObservation[] =
        urlhaus.records.map(
          (record) => ({
            source:
              "URLhaus",
            type:
              record.threat ??
              "Malware Distribution URL",
            description:
              record.status
                ? `URLhaus malware URL — ${record.status}`
                : "URLhaus malware distribution observation",
            malware: null,
            confidence: null,
            firstSeen:
              record.dateAdded ??
              null,
            lastSeen: null,
            tags:
              record.tags ?? [],
          }),
        )

    const observations:
      ThreatObservation[] = [
        ...threatFoxObservations,
        ...urlhausObservations,
      ]

    const evidence =
      buildEvidence({
        threatFox,
        urlhaus,
        otx: otxResult,
      })

    const assessment =
      buildAssessment(
        evidence,
      )

    const urlhausHosts =
      urlhaus.records
        .map(
          (record) =>
            record.host ?? "",
        )
        .filter(Boolean)

    const urlhausIps =
      urlhausHosts.filter(
        (host) =>
          /^(?:\d{1,3}\.){3}\d{1,3}$/.test(
            host,
          ),
      )

    const urlhausDomains =
      urlhausHosts.filter(
        (host) =>
          !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(
            host,
          ),
      )

    const ips =
      unique([
        ...(type === "ip"
          ? [indicator]
          : []),
        ...dnsResult.ips,
        ...urlhausIps,
      ])

    const [
      rdapResult,
      bgpResult,
    ] =
      await Promise.all([
        enrichRdap(ips),
        enrichBgp(ips),
      ])

    const providers =
      unique(
        rdapResult.records
          .map(
            (record) =>
              record.organization ??
              record.name ??
              "",
          ),
      )

    const countries =
      unique(
        rdapResult.records
          .map(
            (record) =>
              record.country ?? "",
          ),
      )

    const domains =
      unique([
        ...dnsResult.domains,
        ...urlhausDomains,
      ]).filter(
        (domain) =>
          domain !== indicator,
      )

    const relationships =
      buildRelationships({
        indicator,
        threatFox,
        urlhaus,
        dnsRelationships:
          dnsResult.relationships,
      })

    const threatFoxEvidence =
      evidence.filter(
        (item) =>
          item.source ===
          "ThreatFox",
      )

    const urlhausEvidence =
      evidence.filter(
        (item) =>
          item.source ===
          "URLhaus",
      )

    const dnsContribution:
      string[] = []

    if (
      dnsResult.dns.a.length > 0 ||
      dnsResult.dns.aaaa.length > 0
    ) {
      dnsContribution.push(
        "IP resolution",
      )
    }

    if (
      dnsResult.dns.ns.length > 0
    ) {
      dnsContribution.push(
        "Nameservers",
      )
    }

    if (
      dnsResult.dns.mx.length > 0
    ) {
      dnsContribution.push(
        "Mail infrastructure",
      )
    }

    if (
      dnsResult.dns.cname.length > 0
    ) {
      dnsContribution.push(
        "CNAME relationships",
      )
    }

    if (
      dnsResult.dns.reverse.length >
      0
    ) {
      dnsContribution.push(
        "Reverse DNS",
      )
    }

    const sources:
      IntelligenceSource[] = [
        {
          name: "ThreatFox",
          status:
            threatFox.status,
          evidenceFound:
            threatFoxEvidence.length >
            0,
          evidenceCount:
            threatFoxEvidence.length,
          contribution:
            threatFoxEvidence.length >
            0
              ? [
                  "IOC reputation",
                  "Threat classification",
                  ...(malware.length > 0
                    ? [
                        "Malware association",
                      ]
                    : []),
                  ...(threatFox.records.some(
                    (record) =>
                      typeof record
                        .confidence_level ===
                      "number",
                  )
                    ? [
                        "Source confidence",
                      ]
                    : []),
                ]
              : [],
        },
        {
          name: "URLhaus",
          status:
            urlhaus.status,
          evidenceFound:
            urlhausEvidence.length >
            0,
          evidenceCount:
            urlhausEvidence.length,
          contribution:
            urlhausEvidence.length >
            0
              ? [
                  "Malware distribution record",
                  "Observed URL context",
                ]
              : [],
        },
        {
          name: "OTX",
          status:
            otxResult.status,
          evidenceFound:
            otxResult.pulseCount > 0,
          evidenceCount:
            otxResult.pulses.length,
          contribution:
            otxResult.pulseCount > 0
              ? [
                  `${otxResult.pulseCount} Pulse association${
                    otxResult.pulseCount === 1
                      ? ""
                      : "s"
                  }`,
                  ...(otxResult.pulses.some(
                    (pulse) =>
                      pulse.malwareFamilies.length > 0,
                  )
                    ? ["Malware context"]
                    : []),
                  ...(otxResult.pulses.some(
                    (pulse) =>
                      Boolean(
                        pulse.adversary,
                      ),
                  )
                    ? ["Adversary context"]
                    : []),
                ]
              : [],
        },
        {
          name: "DNS",
          status:
            type === "domain" ||
            type === "url" ||
            type === "ip"
              ? "connected"
              : "not_configured",
          evidenceFound: false,
          evidenceCount: 0,
          contribution:
            dnsContribution,
        },
        {
          name: "RDAP",
          status:
            ips.length > 0
              ? rdapResult.status
              : "not_configured",
          evidenceFound: false,
          evidenceCount: 0,
          contribution:
            rdapResult.records.length > 0
              ? [
                  "Registered network",
                  ...(providers.length > 0
                    ? ["Registered organization"]
                    : []),
                  ...(countries.length > 0
                    ? ["Registration country"]
                    : []),
                  "Registry provenance",
                ]
              : [],
        },
        {
          name: "RIPEstat BGP",
          status:
            ips.length > 0
              ? bgpResult.status
              : "not_configured",
          evidenceFound: false,
          evidenceCount: 0,
          contribution:
            bgpResult.records.length > 0
              ? [
                  "Announced prefix",
                  "Origin ASN",
                  ...(bgpResult.records.some(
                    (record) =>
                      Boolean(
                        record.asHolder,
                      ),
                  )
                    ? ["AS holder"]
                    : []),
                  "Routing context",
                ]
              : [],
        },
      ]

    const result:
      InvestigationResult = {
        indicator: {
          value: indicator,
          type,
        },
        assessment,
        evidence,
        infrastructure: {
          ips,
          domains,
          asns:
            unique(
              bgpResult.records.flatMap(
                (record) =>
                  record.asns.map(
                    (asn) =>
                      `AS${asn}`,
                  ),
              ),
            ),
          providers,
          countries,
          dns:
            dnsResult.dns,
          rdap:
            rdapResult.records,
          bgp:
            bgpResult.records,
        },
        malware,
        otx: {
          pulseCount:
            otxResult.pulseCount,
          pulses:
            otxResult.pulses,
        },
        observations,
        relationships,
        sources,
        investigatedAt:
          new Date()
            .toISOString(),
      }

    return res.json(result)
  },
)

export default router