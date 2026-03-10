import { useState } from "react";
import { Search, Shield, ShieldAlert, ShieldCheck, Globe, Server, Tag, AlertTriangle } from "lucide-react";
import logo from "./assets/logo.png";

const BACKEND_URL = "http://localhost/backend/analyze.php";

function ScoreRing({ score }) {
  const color = score >= 70 ? "#ef4444" : score >= 30 ? "#f97316" : "#22c55e";
  const label = score >= 70 ? "Malicious" : score >= 30 ? "Suspicious" : "Clean";
  const r = 54;
  const circ = 2 * Math.PI * r;
  const dash = ((100 - score) / 100) * circ;

  return (
    <div className="score-ring-container">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={r} fill="none" stroke="#1e293b" strokeWidth="12" />
        <circle
          cx="70" cy="70" r={r} fill="none"
          stroke={color} strokeWidth="12"
          strokeDasharray={circ}
          strokeDashoffset={dash}
          strokeLinecap="round"
          transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dashoffset 1s ease" }}
        />
        <text x="70" y="65" textAnchor="middle" fill={color} fontSize="26" fontWeight="bold">{score}%</text>
        <text x="70" y="85" textAnchor="middle" fill="#94a3b8" fontSize="13">{label}</text>
      </svg>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, color }) {
  return (
    <div className="stat-card">
      <Icon size={20} color={color} />
      <div>
        <div className="stat-value" style={{ color }}>{value ?? "N/A"}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

export default function App() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function analyze() {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`${BACKEND_URL}?query=${encodeURIComponent(query.trim())}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setResult(data);
    } catch (e) {
      setError(e.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  const threatColor = result
    ? result.score >= 70 ? "#ef4444" : result.score >= 30 ? "#f97316" : "#22c55e"
    : "#64748b";

  return (
    <div className="app">
      <div className="header">
        <img src={logo} alt="logo" style={{ width: "80px", height: "80px", objectFit: "contain" }} />
        <h1>Threat<span>Analyzer</span></h1>
        <p>Analyze IPs & Domains against threat intelligence sources</p>
      </div>

      <div className="search-bar">
        <input
          type="text"
          placeholder="Enter IP address or domain (e.g. 8.8.8.8 or google.com)"
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === "Enter" && analyze()}
        />
        <button onClick={analyze} disabled={loading}>
          {loading ? <span className="spinner" /> : <Search size={18} />}
          {loading ? "Analyzing..." : "Analyze"}
        </button>
      </div>

      {error && (
        <div className="error-box">
          <AlertTriangle size={18} /> {error}
        </div>
      )}

      {result && (
        <div className="results">
          <div className="results-header">
            <div>
              <h2>{result.query}</h2>
              <span className="badge">{result.type}</span>
            </div>
            <ScoreRing score={result.score} />
          </div>

          <div className="stats-grid">
            <StatCard icon={ShieldAlert} label="Malicious Engines" value={result.malicious} color="#ef4444" />
            <StatCard icon={AlertTriangle} label="Suspicious Engines" value={result.suspicious} color="#f97316" />
            <StatCard icon={ShieldCheck} label="Harmless Engines" value={result.harmless} color="#22c55e" />
            <StatCard icon={Globe} label="Country" value={result.country} color="#38bdf8" />
            <StatCard icon={Server} label="ISP / Owner" value={result.isp || result.owner} color="#a78bfa" />
            {result.abuse_score !== null && (
              <StatCard icon={ShieldAlert} label="Abuse Score" value={`${result.abuse_score}%`} color="#f97316" />
            )}
          </div>

          {result.categories.length > 0 && (
            <div className="categories">
              <Tag size={16} color="#94a3b8" />
              <span>Categories:</span>
              {result.categories.map((c, i) => <span key={i} className="tag">{c}</span>)}
            </div>
          )}

          <div className="sources">
            <span>Sources:</span>
            <span className="source-badge vt">VirusTotal</span>
            {result.abuse_score !== null && <span className="source-badge abuse">AbuseIPDB</span>}
          </div>
        </div>
      )}

      {!result && !loading && !error && (
        <div className="placeholder">
          <img src={logo} alt="logo" style={{ width: "80px", height: "80px", objectFit: "contain", opacity: 0.2 }} />
          <p>Enter an IP or domain above to start analysis</p>
          <p>This Project Made By ©Idriss Chiheb</p>
        </div>
      )}
    </div>
  );
}