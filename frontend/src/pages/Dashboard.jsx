import { useEffect, useState } from "react";
import { api } from "../api.js";
import { useAuth } from "../AuthContext.jsx";

const FEATURE_LABELS = {
  url_length: "URL length",
  hostname_length: "Hostname length",
  has_https: "HTTPS secured",
  has_ip: "Direct IP host",
  uses_shortener: "Shortener used",
  risky_tld: "Risky TLD",
  subdomain_count: "Subdomains count",
  keyword_hits: "Keyword hits",
  digit_ratio: "Digit ratio",
  entropy: "Shannon entropy",
  has_port: "Custom port used",
  has_at_symbol: "@ character in URL",
  double_slash_redirect: "Double slash redirect",
  email_urgency_hits: "Urgency phrases",
  email_credential_ask: "Credential solicitation",
  email_link_count: "Links in email",
};

const SAMPLE_PRESETS = [
  {
    name: "Phishing Kit URL",
    type: "url",
    content: "http://paypal-secure-login.tk/webscr?cmd=_login",
  },
  {
    name: "Legitimate Wikipedia URL",
    type: "url",
    content: "https://www.wikipedia.org/wiki/Phishing",
  },
  {
    name: "IP Phishing Host",
    type: "url",
    content: "http://192.168.4.22/login/verify-account",
  },
  {
    name: "Urgent Phishing Email",
    type: "email",
    content: `URGENT: Your account will be closed in 24 hours.\nVerify your credentials immediately at:\nhttp://192.168.1.100/login/account-verification`,
  },
];

export default function Dashboard() {
  const { user, logout } = useAuth();
  const [inputType, setInputType] = useState("url");
  const [content, setContent] = useState("");
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [activeSignalTab, setActiveSignalTab] = useState("explanations");

  async function refresh() {
    try {
      const [s, h] = await Promise.all([api.stats(), api.scans()]);
      setStats(s);
      setHistory(h);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function onScan(e) {
    if (e) e.preventDefault();
    if (!content.trim()) return;
    setBusy(true);
    setError("");
    try {
      const data = await api.scan({ input_type: inputType, content });
      setResult(data);
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  function applyPreset(preset) {
    setInputType(preset.type);
    setContent(preset.content);
    setResult(null);
  }

  function getVerdictClass(v) {
    const val = (v || "").toLowerCase();
    if (val.includes("phish")) return "phishing";
    if (val.includes("suspicious")) return "suspicious";
    return "legitimate";
  }

  const verdictTone = result ? getVerdictClass(result.verdict) : "";

  return (
    <div className="shell">
      {/* Top Navigation */}
      <header className="topbar">
        <div className="brand-header-wrap">
          <img src="/logo.png" alt="PhishGuard Mascot" className="brand-logo" />
          <div className="brand-group">
            <div className="brand-badge">
              <span className="pulse-indicator"></span>
              PHISHGUARD AI DEFENSE SUITE
            </div>
            <h1>Dual-Engine Threat Detection Console</h1>
            <p className="subtitle">
              Combines Random Forest Machine Learning (33 structural & lexical signals) with live Threat Reputation Feeds (VirusTotal & Google Safe Browsing).
            </p>
          </div>
        </div>
        <div className="user-chip">
          <div className="avatar">{user?.full_name?.charAt(0) || "U"}</div>
          <div className="user-info">
            <span className="user-name">{user?.full_name}</span>
            <span className="user-role">{user?.email}</span>
          </div>
          <button className="ghost sm-btn" onClick={logout} type="button">
            Sign out
          </button>
        </div>
      </header>

      {/* Global Defense Stats */}
      <section className="stats-grid">
        <Stat label="Total Scans" value={stats?.total_scans ?? "—"} sub="Historical queries" />
        <Stat
          label="Phishing Threats"
          value={stats?.phishing_count ?? "—"}
          tone="danger"
          sub="High-confidence blocks"
        />
        <Stat
          label="Suspicious Vectors"
          value={stats?.suspicious_count ?? 0}
          tone="warning"
          sub="Heuristic anomalies"
        />
        <Stat
          label="Likely Legitimate"
          value={stats?.legitimate_count ?? "—"}
          tone="ok"
          sub="Standard profiles"
        />
        <Stat
          label="Overall Threat Rate"
          value={stats ? `${Math.round(stats.phishing_rate * 100)}%` : "—"}
          sub="Malicious ratio"
        />
      </section>

      {/* Main Workspace */}
      <div className="workspace">
        {/* Scanner Input Panel */}
        <form className="card scanner-form" onSubmit={onScan}>
          <div className="scanner-header">
            <div className="tabs">
              <button
                type="button"
                className={inputType === "url" ? "active" : ""}
                onClick={() => setInputType("url")}
              >
                🌐 URL Threat Inspector
              </button>
              <button
                type="button"
                className={inputType === "email" ? "active" : ""}
                onClick={() => setInputType("email")}
              >
                ✉️ Email Payload Scanner
              </button>
            </div>
          </div>

          {/* Quick Presets */}
          <div className="preset-bar">
            <span className="preset-label">Test Samples:</span>
            {SAMPLE_PRESETS.map((p) => (
              <button
                key={p.name}
                type="button"
                className="preset-btn"
                onClick={() => applyPreset(p)}
              >
                {p.name}
              </button>
            ))}
          </div>

          <div className="input-wrap">
            <textarea
              required
              minLength={4}
              placeholder={
                inputType === "url"
                  ? "Enter URL (e.g. https://example.com/login or http://suspicious-site.tk)"
                  : "Paste email body or headers (e.g. From:, Subject:, urgent body text, embedded links)..."
              }
              value={content}
              onChange={(e) => setContent(e.target.value)}
            />
            <div className="input-meta">
              <span>{content.length} characters</span>
              <div className="security-pills">
                <span className="pill">🌲 Random Forest (33 Features)</span>
                <span className="pill">🛡️ Threat Feeds (VT & GSB)</span>
                <span className="pill">⚡ Real-time Audit</span>
              </div>
            </div>
          </div>

          {error && <div className="error-alert">⚠️ {error}</div>}

          <button className="primary-scan-btn" type="submit" disabled={busy || !content.trim()}>
            {busy ? (
              <span className="busy-spin">Analyzing Threat Signals…</span>
            ) : (
              <span>Run Phishing Threat Analysis →</span>
            )}
          </button>
        </form>

        {/* Threat Analysis Report Card */}
        <div className="card result-card">
          {!result ? (
            <div className="empty-state">
              <img src="/logo.png" alt="PhishGuard Mascot" className="empty-state-mascot" />
              <h3>Ready for Security Assessment</h3>
              <p className="muted">
                Submit a URL or email message to trigger dual-engine security evaluation:
              </p>
              <div className="engine-checklist">
                <div>✓ <strong>Random Forest ML Model:</strong> 33 lexical, structural & entropy features (up to 60 pts)</div>
                <div>✓ <strong>Threat Reputation Feeds:</strong> VirusTotal API v3 & Google Safe Browsing API v4 (up to 40 pts)</div>
              </div>
            </div>
          ) : (
            <div className="analysis-report">
              {/* Verdict Header Banner */}
              <div className={`verdict-banner ${verdictTone}`}>
                <div className="verdict-main">
                  <span className="verdict-badge-label">FINAL VERDICT</span>
                  <h2 className="verdict-title">{result.verdict}</h2>
                </div>
                <div className="score-meter">
                  <div className="score-number">{result.risk_score}</div>
                  <div className="score-details">
                    <span className="score-max">/ 100</span>
                    <span className="score-tag">
                      {result.risk_score >= 65
                        ? "High Threat Risk"
                        : result.risk_score >= 35
                        ? "Moderate Suspicion"
                        : "Low Automated Risk"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Model Confidence & Component Contribution Bar */}
              <div className="score-breakdown-box">
                <div className="breakdown-header">
                  <span>Transparent Risk Score Composition</span>
                  <span className="ml-prob">
                    ML Probability: <strong>{Math.round(result.ml_score * 100)}%</strong>
                  </span>
                </div>
                <div className="component-bars">
                  <div className="comp-item">
                    <div className="comp-label">
                      <span>Random Forest ML (Lexical/Structural)</span>
                      <code>{result.signals?.components?.ml ?? "—"} / 60 pts</code>
                    </div>
                    <div className="comp-track">
                      <div
                        className="comp-fill ml-fill"
                        style={{ width: `${Math.min(100, ((result.signals?.components?.ml || 0) / 60) * 100)}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="comp-item">
                    <div className="comp-label">
                      <span>Threat Reputation Feeds (VT & GSB)</span>
                      <code>{result.signals?.components?.reputation ?? "—"} / 40 pts</code>
                    </div>
                    <div className="comp-track">
                      <div
                        className="comp-fill rep-fill"
                        style={{ width: `${Math.min(100, ((result.signals?.components?.reputation || 0) / 40) * 100)}%` }}
                      ></div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Mandatory Safety Notice & Limitations Banner */}
              <div className="disclaimer-alert">
                <div className="disclaimer-icon">⚠️</div>
                <div className="disclaimer-body">
                  <strong>Security Notice & Limitations</strong>
                  <p>
                    {result.limitations ||
                      "No automated scanner can guarantee a URL is 100% safe. 'Likely Legitimate' denotes low automated indicators; always verify the domain in the address bar and exercise caution before entering credentials."}
                  </p>
                </div>
              </div>

              {/* Signal Explorer Tabs */}
              <div className="signal-tabs">
                <button
                  type="button"
                  className={activeSignalTab === "explanations" ? "active" : ""}
                  onClick={() => setActiveSignalTab("explanations")}
                >
                  Explanations ({result.explanations?.length || 0})
                </button>
                <button
                  type="button"
                  className={activeSignalTab === "reputation" ? "active" : ""}
                  onClick={() => setActiveSignalTab("reputation")}
                >
                  Reputation Feeds
                </button>
                <button
                  type="button"
                  className={activeSignalTab === "features" ? "active" : ""}
                  onClick={() => setActiveSignalTab("features")}
                >
                  Lexical & ML Features
                </button>
              </div>

              {/* Signal Tab Content */}
              <div className="signal-content">
                {activeSignalTab === "explanations" && (
                  <ul className="explanations-list">
                    {result.explanations?.map((item, idx) => (
                      <li key={idx} className={item.startsWith("CRITICAL") ? "critical-reason" : ""}>
                        <span className="bullet-icon">
                          {item.startsWith("CRITICAL") ? "🚨" : verdictTone === "phishing" ? "⚠️" : "✓"}
                        </span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                )}

                {activeSignalTab === "reputation" && (
                  <div className="reputation-grid">
                    <div className="intel-card">
                      <div className="intel-head">
                        <h4>VirusTotal API v3</h4>
                        <span
                          className={`status-pill ${
                            result.signals?.reputation?.virustotal?.is_malicious
                              ? "danger"
                              : result.signals?.reputation?.virustotal?.status === "checked"
                              ? "clean"
                              : "unknown"
                          }`}
                        >
                          {result.signals?.reputation?.virustotal?.is_malicious
                            ? "MALICIOUS"
                            : result.signals?.reputation?.virustotal?.status === "checked"
                            ? "CLEAN"
                            : "UNKNOWN"}
                        </span>
                      </div>
                      <p className="intel-detail">
                        {result.signals?.reputation?.virustotal?.details || "No threat vendor detections recorded."}
                      </p>
                      {result.signals?.reputation?.virustotal?.total_engines > 0 && (
                        <div className="ratio-stat">
                          Detections: <strong>{result.signals.reputation.virustotal.malicious_count}</strong> / {result.signals.reputation.virustotal.total_engines} engines
                        </div>
                      )}
                    </div>

                    <div className="intel-card">
                      <div className="intel-head">
                        <h4>Google Safe Browsing v4</h4>
                        <span
                          className={`status-pill ${
                            result.signals?.reputation?.google_safebrowsing?.is_malicious
                              ? "danger"
                              : result.signals?.reputation?.google_safebrowsing?.status === "checked"
                              ? "clean"
                              : "unknown"
                          }`}
                        >
                          {result.signals?.reputation?.google_safebrowsing?.is_malicious
                            ? "THREAT MATCH"
                            : result.signals?.reputation?.google_safebrowsing?.status === "checked"
                            ? "CLEAN"
                            : "UNKNOWN"}
                        </span>
                      </div>
                      <p className="intel-detail">
                        {result.signals?.reputation?.google_safebrowsing?.details || "No threats matching social engineering or malware."}
                      </p>
                      {result.signals?.reputation?.google_safebrowsing?.threat_types?.length > 0 && (
                        <div className="ratio-stat danger-text">
                          Matches: {result.signals.reputation.google_safebrowsing.threat_types.join(", ")}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {activeSignalTab === "features" && (
                  <div className="feature-grid">
                    {Object.entries(FEATURE_LABELS).map(([key, label]) => (
                      <div key={key} className="feature">
                        <span>{label}</span>
                        <code>{String(result.features[key] ?? 0)}</code>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Recent Threats Table */}
      <section className="card table-card">
        <div className="table-header">
          <h2>High-Priority Threats Intercepted</h2>
          <span className="table-badge">{stats?.recent_threats?.length || 0} recorded</span>
        </div>
        {!stats?.recent_threats?.length ? (
          <p className="muted">No threat verdicts recorded yet.</p>
        ) : (
          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Type</th>
                  <th>Payload Preview</th>
                  <th>Risk Score</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {stats.recent_threats.map((row) => (
                  <tr key={row.id}>
                    <td>{new Date(row.created_at).toLocaleString()}</td>
                    <td>
                      <span className="type-tag">{row.input_type.toUpperCase()}</span>
                    </td>
                    <td className="preview-cell">{row.content_preview}</td>
                    <td>
                      <span className="risk-score-pill">{row.risk_score ?? Math.round(row.confidence * 100)}</span>
                    </td>
                    <td>
                      <span className={`verdict-pill ${getVerdictClass(row.verdict)}`}>
                        {row.verdict}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Scan History Table */}
      <section className="card table-card">
        <div className="table-header">
          <h2>Audit & Scan History</h2>
          <span className="table-badge">{history.length} scans</span>
        </div>
        {!history.length ? (
          <p className="muted">All scans are logged persistently in MongoDB per user account.</p>
        ) : (
          <div className="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Type</th>
                  <th>Verdict</th>
                  <th>Risk Score</th>
                  <th>Payload Preview</th>
                </tr>
              </thead>
              <tbody>
                {history.map((row) => (
                  <tr key={row.id}>
                    <td>{new Date(row.created_at).toLocaleString()}</td>
                    <td>
                      <span className="type-tag">{row.input_type.toUpperCase()}</span>
                    </td>
                    <td>
                      <span className={`verdict-pill ${getVerdictClass(row.verdict)}`}>
                        {row.verdict}
                      </span>
                    </td>
                    <td>
                      <span className="risk-score-pill">{row.risk_score ?? Math.round(row.confidence * 100)}</span>
                    </td>
                    <td className="preview-cell">{row.content_preview}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function Stat({ label, value, tone, sub }) {
  return (
    <div className={`stat card ${tone || ""}`}>
      <p className="stat-label">{label}</p>
      <strong className="stat-value">{value}</strong>
      {sub && <span className="stat-sub">{sub}</span>}
    </div>
  );
}
