import {
  Binoculars,
  FileBarChart,
  FolderKanban,
  Home,
  Network,
  Radar,
  Settings,
  Shield,
  Telescope,
} from "lucide-react"

import type { Page } from "../types/app"

type SidebarProps = {
  page: Page
  onNavigate: (page: Page) => void
}

const navigation: {
  id: Page
  label: string
  icon: typeof Home
}[] = [
  {
    id: "home",
    label: "Home",
    icon: Home,
  },
  {
    id: "investigate",
    label: "Investigate",
    icon: Telescope,
  },
  {
    id: "cases",
    label: "Cases",
    icon: FolderKanban,
  },
  {
    id: "indicators",
    label: "Indicators",
    icon: Radar,
  },
  {
    id: "monitoring",
    label: "Monitoring",
    icon: Binoculars,
  },
  {
    id: "reports",
    label: "Reports",
    icon: FileBarChart,
  },
  {
    id: "integrations",
    label: "Integrations",
    icon: Network,
  },
  {
    id: "settings",
    label: "Settings",
    icon: Settings,
  },
]

export default function Sidebar({
  page,
  onNavigate,
}: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">
          <Shield size={19} />
        </div>

        <div>
          <div className="brand-name">
            NIGHTWATCH
          </div>

          <div className="brand-subtitle">
            THREAT INTELLIGENCE RESEARCH
          </div>
        </div>
      </div>

      <nav className="nav">
        {navigation.map((item) => {
          const Icon = item.icon

          return (
            <button
              key={item.id}
              className={`nav-item ${
                page === item.id ? "active" : ""
              }`}
              onClick={() => onNavigate(item.id)}
            >
              <Icon size={16} />

              <span>{item.label}</span>
            </button>
          )
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="system-status">
          <span className="status-dot" />

          <div>
            <strong>Systems Operational</strong>
            <span>Research services online</span>
          </div>
        </div>
      </div>
    </aside>
  )
}