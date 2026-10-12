import {
  randomUUID,
} from "crypto"

import {
  Router,
} from "express"

import database from "../database/database"

import type {
  IndicatorType,
  IntelligenceRelationship,
  IntelligenceSource,
  ThreatObservation,
} from "../types/intelligence"

const router = Router()

type CaseStatus =
  | "active"
  | "closed"

type CreateCaseRequest = {
  title?: string

  indicator: {
    value: string
    type: IndicatorType
  }

  trail?: {
    value: string
    type: IndicatorType
  }[]

  observations?: ThreatObservation[]
  relationships?: IntelligenceRelationship[]
  sources?: IntelligenceSource[]
  notes?: string
}

type UpdateCaseRequest = {
  title?: string
  notes?: string
  status?: CaseStatus
}

type AppendCaseRequest = {
  indicator: {
    value: string
    type: IndicatorType
  }

  trail?: {
    value: string
    type: IndicatorType
  }[]

  observations?: ThreatObservation[]
  relationships?: IntelligenceRelationship[]
  sources?: IntelligenceSource[]
}

type CaseRow = {
  id: string
  caseNumber: string
  title: string
  status: CaseStatus
  originalIndicator: string
  originalIndicatorType: IndicatorType
  notes: string
  createdAt: string
  updatedAt: string
}

type IndicatorRow = {
  value: string
  type: IndicatorType
  position: number
}

type ObservationRow = {
  source: string
  type: string
  description: string
  malware: string | null
  confidence: number | null
  firstSeen: string | null
  lastSeen: string | null
  tags: string
}

type RelationshipRow = {
  source: string
  from: string
  to: string
  relationship: string
  nodeType:
    | "indicator"
    | "domain"
    | "ip"
    | "url"
    | "hash"
    | "malware"
}

type SourceRow = {
  name: string
  status:
    | "connected"
    | "no_record"
    | "error"
    | "not_configured"
}

function getNextCaseNumber() {
  const year =
    new Date().getFullYear()

  const prefix =
    `NW-${year}-`

  const row =
    database
      .prepare(`
        SELECT case_number AS caseNumber
        FROM cases
        WHERE case_number LIKE ?
        ORDER BY case_number DESC
        LIMIT 1
      `)
      .get(
        `${prefix}%`,
      ) as
      | {
          caseNumber: string
        }
      | undefined

  let next = 1

  if (row?.caseNumber) {
    const lastPart =
      row.caseNumber.split("-").pop()

    const parsed =
      Number(lastPart)

    if (
      Number.isFinite(parsed)
    ) {
      next = parsed + 1
    }
  }

  return (
    `${prefix}${String(next).padStart(
      4,
      "0",
    )}`
  )
}

function caseExists(caseId: string) {
  return Boolean(
    database
      .prepare(`
        SELECT id
        FROM cases
        WHERE id = ?
      `)
      .get(caseId),
  )
}

function touchCase(caseId: string) {
  const now =
    new Date().toISOString()

  database
    .prepare(`
      UPDATE cases
      SET updated_at = ?
      WHERE id = ?
    `)
    .run(
      now,
      caseId,
    )

  return now
}

function insertIndicators(
  caseId: string,
  indicators: {
    value: string
    type: IndicatorType
  }[],
) {
  const current =
    database
      .prepare(`
        SELECT COALESCE(
          MAX(position),
          -1
        ) AS maxPosition
        FROM case_indicators
        WHERE case_id = ?
      `)
      .get(caseId) as {
        maxPosition: number
      }

  let position =
    current.maxPosition + 1

  const insert =
    database.prepare(`
      INSERT OR IGNORE INTO
      case_indicators (
        case_id,
        value,
        type,
        position
      )
      VALUES (?, ?, ?, ?)
    `)

  for (const indicator of indicators) {
    const result =
      insert.run(
        caseId,
        indicator.value,
        indicator.type,
        position,
      )

    if (
      result.changes > 0
    ) {
      position += 1
    }
  }
}

function insertObservations(
  caseId: string,
  observations: ThreatObservation[],
) {
  const exists =
    database.prepare(`
      SELECT id
      FROM case_observations
      WHERE case_id = ?
        AND source = ?
        AND type = ?
        AND description = ?
        AND COALESCE(malware, '') =
            COALESCE(?, '')
        AND COALESCE(first_seen, '') =
            COALESCE(?, '')
      LIMIT 1
    `)

  const insert =
    database.prepare(`
      INSERT INTO case_observations (
        case_id,
        source,
        type,
        description,
        malware,
        confidence,
        first_seen,
        last_seen,
        tags
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)

  for (
    const observation
    of observations
  ) {
    const duplicate =
      exists.get(
        caseId,
        observation.source,
        observation.type,
        observation.description,
        observation.malware ?? null,
        observation.firstSeen ?? null,
      )

    if (duplicate) {
      continue
    }

    insert.run(
      caseId,
      observation.source,
      observation.type,
      observation.description,
      observation.malware ?? null,
      observation.confidence ?? null,
      observation.firstSeen ?? null,
      observation.lastSeen ?? null,
      JSON.stringify(
        observation.tags ?? [],
      ),
    )
  }
}

function insertRelationships(
  caseId: string,
  relationships:
    IntelligenceRelationship[],
) {
  const exists =
    database.prepare(`
      SELECT id
      FROM case_relationships
      WHERE case_id = ?
        AND source = ?
        AND from_indicator = ?
        AND to_indicator = ?
        AND relationship = ?
        AND node_type = ?
      LIMIT 1
    `)

  const insert =
    database.prepare(`
      INSERT INTO case_relationships (
        case_id,
        source,
        from_indicator,
        to_indicator,
        relationship,
        node_type
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `)

  for (
    const relationship
    of relationships
  ) {
    const duplicate =
      exists.get(
        caseId,
        relationship.source,
        relationship.from,
        relationship.to,
        relationship.relationship,
        relationship.nodeType,
      )

    if (duplicate) {
      continue
    }

    insert.run(
      caseId,
      relationship.source,
      relationship.from,
      relationship.to,
      relationship.relationship,
      relationship.nodeType,
    )
  }
}

function insertSources(
  caseId: string,
  sources: IntelligenceSource[],
) {
  const find =
    database.prepare(`
      SELECT id
      FROM case_sources
      WHERE case_id = ?
        AND name = ?
      LIMIT 1
    `)

  const insert =
    database.prepare(`
      INSERT INTO case_sources (
        case_id,
        name,
        status
      )
      VALUES (?, ?, ?)
    `)

  const update =
    database.prepare(`
      UPDATE case_sources
      SET status = ?
      WHERE case_id = ?
        AND name = ?
    `)

  for (const source of sources) {
    const existing =
      find.get(
        caseId,
        source.name,
      )

    if (existing) {
      update.run(
        source.status,
        caseId,
        source.name,
      )
    } else {
      insert.run(
        caseId,
        source.name,
        source.status,
      )
    }
  }
}

/*
 * CREATE CASE
 */

router.post(
  "/",
  (req, res) => {
    const body =
      req.body as Partial<CreateCaseRequest>

    if (
      !body.indicator?.value ||
      !body.indicator?.type
    ) {
      return res.status(400).json({
        error:
          "Case indicator is required.",
      })
    }

    const now =
      new Date().toISOString()

    const caseId =
      `NW-${randomUUID()}`

    const caseNumber =
      getNextCaseNumber()

    const title =
      body.title?.trim() ||
      `Investigation — ${body.indicator.value}`

    const trail =
      body.trail?.length
        ? body.trail
        : [body.indicator]

    const saveCase =
      database.transaction(() => {
        database
          .prepare(`
            INSERT INTO cases (
              id,
              case_number,
              title,
              status,
              original_indicator,
              original_indicator_type,
              notes,
              created_at,
              updated_at
            )
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
          `)
          .run(
            caseId,
            caseNumber,
            title,
            "active",
            body.indicator!.value,
            body.indicator!.type,
            body.notes ?? "",
            now,
            now,
          )

        insertIndicators(
          caseId,
          trail,
        )

        insertObservations(
          caseId,
          body.observations ?? [],
        )

        insertRelationships(
          caseId,
          body.relationships ?? [],
        )

        insertSources(
          caseId,
          body.sources ?? [],
        )
      })

    try {
      saveCase()

      return res.status(201).json({
        id: caseId,
        caseNumber,
        title,
        status: "active",
        createdAt: now,
      })
    } catch (error) {
      console.error(
        "Failed to create case:",
        error,
      )

      return res.status(500).json({
        error:
          "Failed to create research case.",
      })
    }
  },
)

/*
 * LIST CASES
 */

router.get(
  "/",
  (_req, res) => {
    try {
      const cases =
        database
          .prepare(`
            SELECT
              id,

              case_number
                AS caseNumber,

              title,
              status,

              original_indicator
                AS originalIndicator,

              original_indicator_type
                AS originalIndicatorType,

              created_at
                AS createdAt,

              updated_at
                AS updatedAt

            FROM cases

            ORDER BY
              updated_at DESC
          `)
          .all()

      return res.json(cases)
    } catch (error) {
      console.error(
        "Failed to load cases:",
        error,
      )

      return res.status(500).json({
        error:
          "Failed to load research cases.",
      })
    }
  },
)

/*
 * UPDATE CASE METADATA
 */

router.patch(
  "/:id",
  (req, res) => {
    const caseId =
      req.params.id

    if (!caseExists(caseId)) {
      return res.status(404).json({
        error:
          "Research case not found.",
      })
    }

    const body =
      req.body as UpdateCaseRequest

    if (
      body.status !== undefined &&
      body.status !== "active" &&
      body.status !== "closed"
    ) {
      return res.status(400).json({
        error:
          "Case status must be active or closed.",
      })
    }

    const existing =
      database
        .prepare(`
          SELECT
            title,
            notes,
            status
          FROM cases
          WHERE id = ?
        `)
        .get(caseId) as {
          title: string
          notes: string
          status: CaseStatus
        }

    const title =
      body.title !== undefined
        ? body.title.trim()
        : existing.title

    if (!title) {
      return res.status(400).json({
        error:
          "Case title cannot be empty.",
      })
    }

    const notes =
      body.notes !== undefined
        ? body.notes
        : existing.notes

    const status =
      body.status ??
      existing.status

    const now =
      new Date().toISOString()

    database
      .prepare(`
        UPDATE cases
        SET
          title = ?,
          notes = ?,
          status = ?,
          updated_at = ?
        WHERE id = ?
      `)
      .run(
        title,
        notes,
        status,
        now,
        caseId,
      )

    return res.json({
      id: caseId,
      title,
      notes,
      status,
      updatedAt: now,
    })
  },
)

/*
 * APPEND INVESTIGATION
 */

router.post(
  "/:id/intelligence",
  (req, res) => {
    const caseId =
      req.params.id

    if (!caseExists(caseId)) {
      return res.status(404).json({
        error:
          "Research case not found.",
      })
    }

    const body =
      req.body as Partial<AppendCaseRequest>

    if (
      !body.indicator?.value ||
      !body.indicator?.type
    ) {
      return res.status(400).json({
        error:
          "Investigation indicator is required.",
      })
    }

    try {
      const append =
        database.transaction(() => {
          insertIndicators(
            caseId,
            body.trail?.length
              ? body.trail
              : [body.indicator!],
          )

          insertObservations(
            caseId,
            body.observations ?? [],
          )

          insertRelationships(
            caseId,
            body.relationships ?? [],
          )

          insertSources(
            caseId,
            body.sources ?? [],
          )

          return touchCase(caseId)
        })

      const updatedAt =
        append()

      return res.json({
        id: caseId,
        updatedAt,
      })
    } catch (error) {
      console.error(
        "Failed to append intelligence:",
        error,
      )

      return res.status(500).json({
        error:
          "Failed to add intelligence to case.",
      })
    }
  },
)

/*
 * DELETE CASE
 */

router.delete(
  "/:id",
  (req, res) => {
    const caseId =
      req.params.id

    const result =
      database
        .prepare(`
          DELETE FROM cases
          WHERE id = ?
        `)
        .run(caseId)

    if (
      result.changes === 0
    ) {
      return res.status(404).json({
        error:
          "Research case not found.",
      })
    }

    return res.status(204).send()
  },
)

/*
 * GET ONE CASE
 */

router.get(
  "/:id",
  (req, res) => {
    try {
      const caseId =
        req.params.id

      const researchCase =
        database
          .prepare(`
            SELECT
              id,

              case_number
                AS caseNumber,

              title,
              status,

              original_indicator
                AS originalIndicator,

              original_indicator_type
                AS originalIndicatorType,

              notes,

              created_at
                AS createdAt,

              updated_at
                AS updatedAt

            FROM cases

            WHERE id = ?
          `)
          .get(caseId) as
          | CaseRow
          | undefined

      if (!researchCase) {
        return res.status(404).json({
          error:
            "Research case not found.",
        })
      }

      const indicators =
        database
          .prepare(`
            SELECT
              value,
              type,
              position
            FROM case_indicators
            WHERE case_id = ?
            ORDER BY position ASC
          `)
          .all(
            caseId,
          ) as IndicatorRow[]

      const observationRows =
        database
          .prepare(`
            SELECT
              source,
              type,
              description,
              malware,
              confidence,

              first_seen
                AS firstSeen,

              last_seen
                AS lastSeen,

              tags

            FROM case_observations

            WHERE case_id = ?

            ORDER BY id ASC
          `)
          .all(
            caseId,
          ) as ObservationRow[]

      const observations =
        observationRows.map(
          (observation) => {
            let tags: string[] = []

            try {
              const parsed =
                JSON.parse(
                  observation.tags,
                )

              if (
                Array.isArray(parsed)
              ) {
                tags =
                  parsed.filter(
                    (
                      value,
                    ): value is string =>
                      typeof value ===
                      "string",
                  )
              }
            } catch {
              tags = []
            }

            return {
              source:
                observation.source,

              type:
                observation.type,

              description:
                observation.description,

              malware:
                observation.malware,

              confidence:
                observation.confidence,

              firstSeen:
                observation.firstSeen,

              lastSeen:
                observation.lastSeen,

              tags,
            }
          },
        )

      const relationships =
        database
          .prepare(`
            SELECT
              source,

              from_indicator
                AS "from",

              to_indicator
                AS "to",

              relationship,

              node_type
                AS nodeType

            FROM case_relationships

            WHERE case_id = ?

            ORDER BY id ASC
          `)
          .all(
            caseId,
          ) as RelationshipRow[]

      const sources =
        database
          .prepare(`
            SELECT
              name,
              status

            FROM case_sources

            WHERE case_id = ?

            ORDER BY id ASC
          `)
          .all(
            caseId,
          ) as SourceRow[]

      return res.json({
        ...researchCase,

        indicators:
          indicators.map(
            ({
              value,
              type,
            }) => ({
              value,
              type,
            }),
          ),

        observations,
        relationships,
        sources,
      })
    } catch (error) {
      console.error(
        "Failed to load case:",
        error,
      )

      return res.status(500).json({
        error:
          "Failed to load research case.",
      })
    }
  },
)

export default router