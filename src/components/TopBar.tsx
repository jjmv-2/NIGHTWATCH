import { Bell, Search } from "lucide-react"

export default function TopBar() {
  return (
    <header className="topbar">
      <div className="topbar-spacer" />

      <div className="topbar-search">
        <Search size={14} />

        <input
          type="text"
          placeholder="Search cases..."
        />
      </div>

      <button
        className="icon-button"
        aria-label="Notifications"
      >
        <Bell size={16} />
      </button>

      <div className="avatar">
        NW
      </div>
    </header>
  )
}