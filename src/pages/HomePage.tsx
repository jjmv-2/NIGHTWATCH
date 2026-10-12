import {
  ArrowRight,
  Clock3,
  FileKey2,
  Globe2,
  Hash,
  Network,
  Search,
} from "lucide-react"

import {
  useState,
  type KeyboardEvent,
} from "react"

import type {
  IndicatorType,
  ResearchItem,
} from "../types/app"

type HomePageProps = {
  recentResearch: ResearchItem[]
  onInvestigate: (value: string) => void
}

function getIndicatorIcon(
  type: IndicatorType,
) {
  switch (type) {
    case "domain":
      return Globe2

    case "ip":
      return Network

    case "hash":
      return Hash

    case "cve":
      return FileKey2

    default:
      return Search
  }
}

export default function HomePage({
  recentResearch,
  onInvestigate,
}: HomePageProps) {
  const [indicator, setIndicator] =
    useState("")

  function submit() {
    const value = indicator.trim()

    if (!value) return

    onInvestigate(value)
  }

  function handleKeyDown(
    event: KeyboardEvent<HTMLInputElement>,
  ) {
    if (event.key === "Enter") {
      submit()
    }
  }

  return (
    <div className="home-page">
      <div className="hero">
        <div className="eyebrow">
          PASSIVE THREAT RESEARCH
        </div>

        <h1>
          Investigate an Indicator
        </h1>

        <p>
          Enter a domain, IP address, URL,
          file hash, or CVE to begin researching
          threat intelligence and related
          infrastructure.
        </p>

        <div className="investigation-search">
          <div className="investigation-input">
            <Search size={17} />

            <input
              value={indicator}
              onChange={(event) =>
                setIndicator(
                  event.target.value,
                )
              }
              onKeyDown={handleKeyDown}
              placeholder="domain, IP, URL, hash, or CVE..."
              autoFocus
            />
          </div>

          <button
            className="primary-button"
            onClick={submit}
          >
            Investigate
            <ArrowRight size={16} />
          </button>
        </div>

        <div className="supported-types">
          <span>DOMAIN</span>
          <span>IP</span>
          <span>URL</span>
          <span>SHA256</span>
          <span>CVE</span>
        </div>
      </div>

      <section className="recent-section">
        <div className="section-header">
          <div>
            <h2>Recent Research</h2>

            <p>
              Continue previous investigations.
            </p>
          </div>
        </div>

        <div className="recent-card">
          {recentResearch.length === 0 ? (
            <div className="empty-state">
              <Search size={22} />

              <strong>
                No investigations yet
              </strong>

              <span>
                Search your first indicator
                above.
              </span>
            </div>
          ) : (
            recentResearch.map((item) => {
              const Icon =
                getIndicatorIcon(item.type)

              return (
                <button
                  key={item.id}
                  className="research-row"
                  onClick={() =>
                    onInvestigate(item.value)
                  }
                >
                  <div className="research-main">
                    <div className="research-icon">
                      <Icon size={15} />
                    </div>

                    <div>
                      <strong>
                        {item.value}
                      </strong>

                      <span>
                        {item.type.toUpperCase()}
                      </span>
                    </div>
                  </div>

                  <div className="research-time">
                    <Clock3 size={13} />
                    {item.investigatedAt}
                  </div>
                </button>
              )
            })
          )}
        </div>
      </section>
    </div>
  )
}