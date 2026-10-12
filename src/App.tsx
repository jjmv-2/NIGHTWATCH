import { useState } from "react"

import Sidebar from "./components/Sidebar"
import TopBar from "./components/TopBar.tsx"

import HomePage from "./pages/HomePage"
import InvestigatePage from "./pages/InvestigatePage.tsx"
import CasesPage from "./pages/CasesPage.tsx"
import CaseDetailPage from "./pages/CaseDetailPage.tsx"

import type {
  IndicatorType,
  InvestigationTrailItem,
  Page,
  ResearchItem,
} from "./types/app"

function detectIndicatorType(
  value: string,
): IndicatorType {
  const trimmed = value.trim()

  if (
    /^CVE-\d{4}-\d{4,}$/i.test(trimmed)
  ) {
    return "cve"
  }

  if (
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(
      trimmed,
    )
  ) {
    const octets = trimmed
      .split(".")
      .map(Number)

    if (
      octets.every(
        (octet) =>
          octet >= 0 &&
          octet <= 255,
      )
    ) {
      return "ip"
    }
  }

  if (
    /^https?:\/\/\S+$/i.test(trimmed)
  ) {
    return "url"
  }

  if (
    /^[a-f0-9]{32}$/i.test(trimmed) ||
    /^[a-f0-9]{40}$/i.test(trimmed) ||
    /^[a-f0-9]{64}$/i.test(trimmed)
  ) {
    return "hash"
  }

  if (
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(
      trimmed,
    )
  ) {
    return "domain"
  }

  return "unknown"
}

function App() {
  const [page, setPage] =
    useState<Page>("home")

  const [
    selectedIndicator,
    setSelectedIndicator,
  ] = useState("")

  const [
    selectedCaseId,
    setSelectedCaseId,
  ] = useState<string | null>(
    null,
  )

  /*
   * Tracks whether the analyst is currently
   * continuing research inside an existing case.
   */
  const [
    activeCaseId,
    setActiveCaseId,
  ] = useState<string | null>(
    null,
  )

  const [
    recentResearch,
    setRecentResearch,
  ] = useState<ResearchItem[]>([])

  const [
    investigationTrail,
    setInvestigationTrail,
  ] = useState<InvestigationTrailItem[]>(
    [],
  )

  function addRecentResearch(
    value: string,
    type: IndicatorType,
  ) {
    const item: ResearchItem = {
      id: crypto.randomUUID(),
      value,
      type,
      investigatedAt: "Just now",
    }

    setRecentResearch(
      (current) => [
        item,
        ...current.filter(
          (existing) =>
            existing.value !== value,
        ),
      ].slice(0, 5),
    )
  }

  /*
   * =====================================
   * FRESH INVESTIGATION
   * =====================================
   *
   * A search started from Home or another
   * normal entry point is NOT attached to
   * an existing case.
   */

  function investigate(
    value: string,
  ) {
    const cleanValue =
      value.trim()

    if (!cleanValue) {
      return
    }

    const type =
      detectIndicatorType(
        cleanValue,
      )

    if (type === "unknown") {
      return
    }

    setActiveCaseId(null)

    setSelectedIndicator(
      cleanValue,
    )

    addRecentResearch(
      cleanValue,
      type,
    )

    setInvestigationTrail([
      {
        value: cleanValue,
        type,
      },
    ])

    setSelectedCaseId(null)
    setPage("investigate")
  }

  /*
   * =====================================
   * CONTINUE EXISTING CASE
   * =====================================
   *
   * Used by CaseDetailPage. This keeps the
   * case ID alive while the analyst researches
   * the selected IOC.
   */

  function continueCaseInvestigation(
    value: string,
    caseId?: string,
  ) {
    const cleanValue =
      value.trim()

    if (!cleanValue) {
      return
    }

    const type =
      detectIndicatorType(
        cleanValue,
      )

    if (type === "unknown") {
      return
    }

    setActiveCaseId(
      caseId ?? null,
    )

    setSelectedIndicator(
      cleanValue,
    )

    addRecentResearch(
      cleanValue,
      type,
    )

    setInvestigationTrail([
      {
        value: cleanValue,
        type,
      },
    ])

    setSelectedCaseId(null)
    setPage("investigate")
  }

  /*
   * =====================================
   * PIVOT INVESTIGATION
   * =====================================
   *
   * IMPORTANT:
   * Do not clear activeCaseId here.
   * If this investigation began from a case,
   * every supported pivot remains associated
   * with that same case until saved.
   */

  function pivotInvestigation(
    value: string,
  ) {
    const cleanValue =
      value.trim()

    if (!cleanValue) {
      return
    }

    const type =
      detectIndicatorType(
        cleanValue,
      )

    if (type === "unknown") {
      return
    }

    setSelectedIndicator(
      cleanValue,
    )

    addRecentResearch(
      cleanValue,
      type,
    )

    setInvestigationTrail(
      (currentTrail) => {
        const existingIndex =
          currentTrail.findIndex(
            (trailItem) =>
              trailItem.value ===
              cleanValue,
          )

        if (
          existingIndex !== -1
        ) {
          return currentTrail.slice(
            0,
            existingIndex + 1,
          )
        }

        return [
          ...currentTrail,
          {
            value:
              cleanValue,
            type,
          },
        ]
      },
    )

    setSelectedCaseId(null)
    setPage("investigate")
  }

  /*
   * =====================================
   * CASE NAVIGATION
   * =====================================
   */

  function openCase(
    caseId: string,
  ) {
    setActiveCaseId(null)

    setSelectedCaseId(
      caseId,
    )

    setPage("cases")
  }

  function closeCase() {
    setSelectedCaseId(null)
    setActiveCaseId(null)
    setPage("cases")
  }

  function navigate(
    nextPage: Page,
  ) {
    setSelectedCaseId(null)

    /*
     * Leaving the investigation workspace
     * ends the current case continuation
     * session. Returning to the case and
     * choosing Continue Investigation starts
     * it again explicitly.
     */
    if (
      nextPage !== "investigate"
    ) {
      setActiveCaseId(null)
    }

    setPage(nextPage)
  }

  /*
   * =====================================
   * PAGE RENDERING
   * =====================================
   */

  function renderPage() {
    if (page === "home") {
      return (
        <HomePage
          recentResearch={
            recentResearch
          }
          onInvestigate={
            investigate
          }
        />
      )
    }

    if (
      page === "investigate"
    ) {
      return (
        <InvestigatePage
          indicator={
            selectedIndicator ||
            "No indicator selected"
          }
          onPivot={
            pivotInvestigation
          }
          investigationTrail={
            investigationTrail
          }
          activeCaseId={
            activeCaseId
          }
        />
      )
    }

    if (page === "cases") {
      if (selectedCaseId) {
        return (
          <CaseDetailPage
            caseId={
              selectedCaseId
            }
            onBack={
              closeCase
            }
            onInvestigate={
              continueCaseInvestigation
            }
          />
        )
      }

      return (
        <CasesPage
          onOpenCase={
            openCase
          }
        />
      )
    }

    return (
      <div className="placeholder-page">
        <span className="eyebrow">
          NIGHTWATCH
        </span>

        <h1>
          {page
            .charAt(0)
            .toUpperCase() +
            page.slice(1)}
        </h1>

        <p>
          This workspace will be built
          next.
        </p>
      </div>
    )
  }

  return (
    <div className="app">
      <Sidebar
        page={page}
        onNavigate={
          navigate
        }
      />

      <main className="main">
        <TopBar />

        <div className="content">
          {renderPage()}
        </div>
      </main>
    </div>
  )
}

export default App