import {
  Activity,
  AlertTriangle,
  Database,
  RefreshCcw,
  Search,
  ShieldAlert,
  Signal,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8001";

const severityLabels = {
  high: "High",
  medium: "Medium",
  low: "Low",
};

function App() {
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [summaryResponse, alertsResponse] = await Promise.all([
        fetch(`${API_BASE_URL}/stats/summary`),
        fetch(`${API_BASE_URL}/alerts?limit=100`),
      ]);

      if (!summaryResponse.ok || !alertsResponse.ok) {
        throw new Error("Detector API returned an error.");
      }

      setSummary(await summaryResponse.json());
      setAlerts(await alertsResponse.json());
    } catch (fetchError) {
      setError(fetchError.message || "Failed to load detector data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 15000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const severityCounts = summary?.severity_counts || { high: 0, medium: 0, low: 0 };
  const latestTimestamp = useMemo(() => {
    if (!alerts.length) return "No alerts";
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "medium",
    }).format(new Date(alerts[0].timestamp));
  }, [alerts]);

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Local SOC / SIEM Lab</p>
          <h1>Mini SOC SIEM Lab</h1>
        </div>
        <button className="iconButton" onClick={refresh} title="Refresh data" type="button">
          <RefreshCcw size={18} aria-hidden="true" />
          <span>Refresh</span>
        </button>
      </header>

      {error && (
        <section className="errorBand">
          <AlertTriangle size={18} aria-hidden="true" />
          <span>{error}</span>
        </section>
      )}

      <section className="metricGrid" aria-label="Summary metrics">
        <Metric
          icon={Database}
          label="Events"
          value={summary?.total_events ?? 0}
          loading={loading}
        />
        <Metric
          icon={ShieldAlert}
          label="Alerts"
          value={summary?.total_alerts ?? 0}
          loading={loading}
        />
        <Metric
          icon={AlertTriangle}
          label="High"
          value={severityCounts.high}
          tone="high"
          loading={loading}
        />
        <Metric icon={Activity} label="Latest" value={latestTimestamp} compact loading={loading} />
      </section>

      <section className="contentGrid">
        <div className="panel">
          <PanelHeader icon={Signal} title="Severity" />
          <div className="severityStack">
            {Object.entries(severityLabels).map(([key, label]) => (
              <div className="severityRow" key={key}>
                <span className={`dot ${key}`} />
                <span>{label}</span>
                <strong>{severityCounts[key] ?? 0}</strong>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <PanelHeader icon={Search} title="Attack Types" />
          <RankList items={summary?.alert_type_counts || []} emptyText="No detections yet" />
        </div>

        <div className="panel">
          <PanelHeader icon={Activity} title="Source IP Ranking" />
          <RankList items={summary?.source_ip_ranking || []} emptyText="No alert sources yet" />
        </div>
      </section>

      <section className="alertsSection">
        <div className="sectionHeader">
          <PanelHeader icon={ShieldAlert} title="Latest Alerts" />
          <span>{alerts.length} shown</span>
        </div>
        <div className="tableWrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>IP</th>
                <th>Time</th>
                <th>Path</th>
                <th>Evidence</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td>{alert.alert_type}</td>
                  <td>{alert.ip || "-"}</td>
                  <td>{new Date(alert.timestamp).toLocaleString()}</td>
                  <td className="pathCell">{alert.path || "-"}</td>
                  <td className="evidenceCell">{formatEvidence(alert.evidence)}</td>
                  <td>{alert.status}</td>
                </tr>
              ))}
              {!alerts.length && (
                <tr>
                  <td colSpan="7" className="emptyCell">
                    {loading ? "Loading detector data" : "No alerts detected"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}

function Metric({ icon: Icon, label, value, tone = "", compact = false, loading }) {
  return (
    <div className={`metric ${tone}`}>
      <Icon size={20} aria-hidden="true" />
      <span>{label}</span>
      <strong className={compact ? "compactValue" : ""}>{loading ? "..." : value}</strong>
    </div>
  );
}

function PanelHeader({ icon: Icon, title }) {
  return (
    <div className="panelHeader">
      <Icon size={18} aria-hidden="true" />
      <h2>{title}</h2>
    </div>
  );
}

function RankList({ items, emptyText }) {
  if (!items.length) {
    return <p className="emptyText">{emptyText}</p>;
  }

  return (
    <ol className="rankList">
      {items.map((item) => (
        <li key={item.name}>
          <span>{item.name}</span>
          <strong>{item.count}</strong>
        </li>
      ))}
    </ol>
  );
}

function SeverityBadge({ severity }) {
  const key = severity?.toLowerCase() || "low";
  return <span className={`badge ${key}`}>{severityLabels[key] || severity}</span>;
}

function formatEvidence(evidence) {
  if (!evidence) return "-";
  const preferred =
    evidence.matched_pattern || evidence.matched_indicator || evidence.failed_attempts;
  if (preferred) return String(preferred);
  return JSON.stringify(evidence);
}

export default App;
