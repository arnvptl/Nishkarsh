import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { LayoutDashboard, Shield, ScrollText } from 'lucide-react';
import './Layout.css';

const NAV = [
  { to: '/',       label: 'Dashboard',  icon: LayoutDashboard },
  { to: '/audit',  label: 'Audit Log',  icon: ScrollText },
];

export default function Layout() {
  const loc = useLocation();
  const pageTitle = loc.pathname === '/' ? 'Risk Dashboard'
    : loc.pathname.startsWith('/entity/') ? 'Entity Detail'
    : loc.pathname === '/audit' ? 'Audit Log'
    : 'SAT-SA';

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-title">⚡ SAT-SA</div>
          <div className="logo-subtitle">NCIIPC · Supervisory Analytics</div>
        </div>

        <nav className="sidebar-nav">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div>v1.0.0 · Air-gapped</div>
          <div>AES-256-GCM · SHA-256 audit</div>
        </div>
      </aside>

      <div className="main-content">
        <header className="topbar">
          <div className="topbar-title">{pageTitle}</div>
          <div className="topbar-right">
            <div className="cycle-badge">
              <Shield size={11} />
              Cycle: DEMO
            </div>
          </div>
        </header>

        <main className="page-body">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
