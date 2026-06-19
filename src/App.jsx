import { useState, useEffect } from "react";
import { fetchIpData } from "./services/ipService";
import { fetchAbuseData } from "./services/abuseService";
import { fetchCensysData } from "./services/censysService";
import { fetchVirusTotalData } from "./services/virusTotalService";

import "leaflet/dist/leaflet.css";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";

import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

const getRiskColor = (score) => {
  if (score <= 20)
    return {
      text: "text-emerald-400",
      bg: "bg-emerald-400/10",
      border: "border-emerald-400/30",
      label: "Clean",
      ring: "#34d399",
    };
  if (score <= 60)
    return {
      text: "text-amber-400",
      bg: "bg-amber-400/10",
      border: "border-amber-400/30",
      label: "Suspicious",
      ring: "#fbbf24",
    };
  return {
    text: "text-red-400",
    bg: "bg-red-400/10",
    border: "border-red-400/30",
    label: "Malicious",
    ring: "#f87171",
  };
};
const getSeverityConfig = (s) =>
  ({
    high: {
      dot: "bg-red-400",
      text: "text-red-400",
      badge: "bg-red-400/10 text-red-400 border border-red-400/20",
    },
    medium: {
      dot: "bg-amber-400",
      text: "text-amber-400",
      badge: "bg-amber-400/10 text-amber-400 border border-amber-400/20",
    },
    low: {
      dot: "bg-sky-400",
      text: "text-sky-400",
      badge: "bg-sky-400/10 text-sky-400 border border-sky-400/20",
    },
  })[s] || {};


function RiskGauge({ score }) {
  const cfg = getRiskColor(score);
  const r = 52,
    cx = 68,
    cy = 68;
  const circum = 2 * Math.PI * r;

  const arcLength = (circum * 300) / 360;
  const dash = (score / 100) * arcLength;
  const startAngle = 120 * (Math.PI / 180);
  const x1 = cx + r * Math.cos(startAngle + Math.PI);
  const y1 = cy + r * Math.sin(startAngle + Math.PI);

  const pct = score / 100;
  const strokeDash = circum * pct * 0.83; 
  return (
    <div className="flex flex-col items-center justify-center gap-1">
      <div className="relative" style={{ width: 136, height: 136 }}>
        <svg width="136" height="136" style={{ transform: "rotate(150deg)" }}>
          <circle
            cx="68"
            cy="68"
            r={r}
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="10"
            strokeDasharray={`${arcLength} ${circum}`}
            strokeLinecap="round"
          />
          <circle
            cx="68"
            cy="68"
            r={r}
            fill="none"
            stroke={cfg.ring}
            strokeWidth="10"
            strokeDasharray={`${(score / 100) * arcLength} ${circum}`}
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0 0 6px ${cfg.ring}88)`,
              transition: "stroke-dasharray 0.8s cubic-bezier(.4,0,.2,1)",
            }}
          />
        </svg>
        <div
          className="absolute inset-0 flex flex-col items-center justify-center"
          style={{ paddingTop: 12 }}
        >
          <span className={`text-3xl font-bold tabular-nums ${cfg.text}`}>
            {score}
          </span>
          <span className="text-[11px] text-slate-500 uppercase tracking-widest">
            / 100
          </span>
        </div>
      </div>
      <span
        className={`text-xs font-semibold uppercase tracking-widest px-2 py-0.5 rounded ${cfg.bg} ${cfg.text} border ${cfg.border}`}
      >
        {cfg.label}
      </span>
    </div>
  );
}

function StatCard({ icon, label, value, sub, accent }) {
  return (
    <div
      className={`relative rounded-xl border bg-slate-900/60 backdrop-blur p-4 flex gap-3 items-start overflow-hidden group transition-all duration-200 hover:border-slate-600 ${accent ? "border-slate-700" : "border-slate-800"}`}
    >
      <div
        className={`shrink-0 w-9 h-9 rounded-lg flex items-center justify-center text-base ${accent || "bg-slate-800 text-slate-400"}`}
      >
        {icon}
      </div>
      <div className="min-w-0">
        <p className="text-[11px] text-slate-500 uppercase tracking-wider mb-0.5">
          {label}
        </p>
        <p
          className="text-sm font-semibold text-slate-100 leading-snug truncate"
          title={value}
        >
          {value || "—"}
        </p>
        {sub && (
          <p className="text-[11px] text-slate-500 mt-0.5 truncate">{sub}</p>
        )}
      </div>
      <div className="absolute inset-0 bg-gradient-to-br from-white/0 to-white/0 group-hover:from-white/[0.01] transition-all duration-300 pointer-events-none rounded-xl" />
    </div>
  );
}

function SectionHeader({ title, badge, action }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-2.5">
        <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">
          {title}
        </h2>
        {badge && (
          <span className="text-[10px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
            {badge}
          </span>
        )}
      </div>
      {action && (
        <button className="text-[11px] text-sky-400 hover:text-sky-300 transition-colors">
          {action}
        </button>
      )}
    </div>
  );
}

function PortBadge({ port }) {
  const known = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    9001: "Tor",
    9030: "Tor-Dir",
    21: "FTP",
    25: "SMTP",
    53: "DNS",
    3306: "MySQL",
    5432: "PG",
  };
  const isTor = [9001, 9030].includes(port);
  const isDanger = [21, 23, 3306, 5432, 6379, 27017].includes(port);
  return (
    <span
      className={`inline-flex items-center gap-1 text-[11px] font-mono px-2 py-1 rounded border ${
        isTor
          ? "bg-purple-500/10 text-purple-400 border-purple-500/25"
          : isDanger
            ? "bg-red-400/10 text-red-400 border-red-400/20"
            : "bg-slate-800 text-slate-300 border-slate-700"
      }`}
    >
      {port}
      {known[port] && (
        <span className="opacity-60 font-sans">{known[port]}</span>
      )}
    </span>
  );
}

function BlacklistRow({ name, listed }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-slate-800/60 last:border-0">
      <span className="text-[13px] text-slate-300">{name}</span>
      <span
        className={`text-[11px] font-semibold flex items-center gap-1.5 px-2 py-0.5 rounded-full ${
          listed
            ? "bg-red-400/10 text-red-400"
            : "bg-emerald-400/10 text-emerald-400"
        }`}
      >
        <span
          className={`w-1.5 h-1.5 rounded-full ${listed ? "bg-red-400" : "bg-emerald-400"}`}
        />
        {listed ? "Listed" : "Clean"}
      </span>
    </div>
  );
}

function TimelineItem({ item, last }) {
  const cfg = getSeverityConfig(item.severity);
  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${cfg.dot}`} />
        {!last && <div className="w-px flex-1 bg-slate-800 mt-1" />}
      </div>
      <div className={`pb-4 ${last ? "" : ""}`}>
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-[13px] text-slate-200">{item.event}</span>
          <span
            className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${cfg.badge}`}
          >
            {item.severity}
          </span>
        </div>
        <span className="text-[11px] text-slate-500 font-mono">
          {item.date}
        </span>
      </div>
    </div>
  );
}

function LoadingPulse() {
  return (
    <div className="space-y-3 animate-pulse">
      {[1, 2, 3, 4].map((i) => (
        <div
          key={i}
          className="h-14 rounded-xl bg-slate-800/50"
          style={{ opacity: 1 - i * 0.15 }}
        />
      ))}
    </div>
  );
}

function EmptyState({ icon, title, sub }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <div className="text-4xl mb-3 opacity-20">{icon}</div>
      <p className="text-sm font-medium text-slate-400">{title}</p>
      {sub && <p className="text-[12px] text-slate-600 mt-1">{sub}</p>}
    </div>
  );
}

const NAV = [
  { id: "overview", icon: "⬡", label: "Overview" },
  { id: "threat", icon: "◈", label: "Threat Intel" },
  { id: "infra", icon: "◻", label: "Infrastructure" },
  { id: "geo", icon: "◎", label: "Geolocation" },
  { id: "history", icon: "◷", label: "Timeline" },
];

function Sidebar({ active, onChange, hasData, searchHistory, onHistoryClick }) {
  return (
    <aside className="w-[200px] shrink-0 flex flex-col border-r border-slate-800 bg-slate-950">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-slate-800/60">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-sky-500 to-cyan-400 flex items-center justify-center">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <circle cx="7" cy="7" r="5.5" stroke="white" strokeWidth="1.5" />
              <path
                d="M7 1v6l3.5 2"
                stroke="white"
                strokeWidth="1.2"
                strokeLinecap="round"
              />
            </svg>
          </div>
          <div>
            <p className="text-[11px] font-bold text-white tracking-wide">
              IP INTELLIGENCE
            </p>
            <p className="text-[9px] text-slate-500 uppercase tracking-widest">
              Dashboard
            </p>
          </div>
        </div>
      </div>
      {/* Nav items */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {NAV.map((n) => (
          <button
            key={n.id}
            onClick={() => onChange(n.id)}
            disabled={!hasData && n.id !== "overview"}
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-left transition-all duration-150 text-[13px] disabled:opacity-30 disabled:cursor-not-allowed ${
              active === n.id
                ? "bg-sky-500/15 text-sky-300 border border-sky-500/25"
                : "text-slate-500 hover:text-slate-300 hover:bg-slate-800/50"
            }`}
          >
            <span className="text-base leading-none">{n.icon}</span>
            <span className="font-medium">{n.label}</span>
          </button>
        ))}
      </nav>

      <div className="px-3 mt-4">
        <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
          Recent Searches
        </p>

        {searchHistory.length === 0 ? (
          <p className="text-xs text-slate-600">No searches yet</p>
        ) : (
          <div className="space-y-1">
            {searchHistory.map((item) => (
              <button
                key={item}
                onClick={() => onHistoryClick(item)}
                className="w-full text-left px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-mono"
              >
                {item}
              </button>
            ))}
          </div>
        )}
      </div>
      {/* Footer */}
      <div className="px-4 py-4 border-t border-slate-800/60">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-[10px] text-slate-500">Live · UTC+0</span>
        </div>
      </div>
    </aside>
  );
}



function OverviewPanel({ ip, data, abuseData, censysData, virusTotalData, loading, summary, exportPDF}) {

  
  const blacklistData = {
  VirusTotal:
    (virusTotalData?.data?.attributes?.last_analysis_stats?.malicious ?? 0) > 0,

  AbuseIPDB:
    (abuseData?.abuseConfidenceScore ?? 0) > 50,

  Censys:
    Object.keys(censysData?.vulns || {}).length > 0,
};

const listedCount =
  Object.values(blacklistData).filter(Boolean).length;
  const abuseScore = abuseData?.abuseConfidenceScore ?? 0;
  const vtMalicious =
    virusTotalData?.data?.attributes?.last_analysis_stats?.malicious ?? 0;
  const blacklistHits =
  Object.values(blacklistData || {}).filter(Boolean)
    .length;

const score = Math.round(
  abuseScore * 0.6 +
  Math.min(vtMalicious, 20) * 1.5 +
  blacklistHits * 5
);
  const cfg = getRiskColor(score);

  
  // const listedCount =
  // blacklistData
  //   ? Object.values(blacklistData).filter(Boolean).length
  //   : 0;

  // Normalize Censys fields
  const cTags = censysData?.tags || censysData?.labels || [];
  const cAsn =
    censysData?.asn ||
    (censysData?.autonomous_system?.asn ? `AS${censysData.autonomous_system.asn}` : null) ||
    data?.org?.split(" ")[0] ||
    "—";
  const cPorts =
    censysData?.ports ||
    censysData?.services?.map((s) => s.port).filter(Boolean) ||
    [];
  const cVulns = censysData?.vulns || {};

  return (
    <div className="space-y-6">
      {/* Top banner: IP + risk score */}
      {data && (
        <div className="rounded-2xl border border-slate-800 bg-gradient-to-br from-slate-900 to-slate-950 p-6">
          <div className="flex flex-col lg:flex-row lg:items-center gap-6">
            {/* IP info */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span
                  className={`text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-full ${cfg.bg} ${cfg.text} border ${cfg.border}`}
                >
                  {cfg.label}
                </span>
                {cTags.map((t) => (
                  <span
                    key={t}
                    className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/25 uppercase tracking-wider"
                  >
                    {t}
                  </span>
                ))}
              </div>
              <div className="flex items-center gap-3 mt-2 mb-1">
  <h1 className="text-4xl font-bold font-mono text-white tracking-tight">
    {data.ip}
  </h1>

  {/* <button
    onClick={() => navigator.clipboard.writeText(data.ip)}
    className="px-3 py-1 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700"
  >
    Copy
  </button> */}
  <button
    onClick={exportPDF}
    disabled={!data}
    className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500"
  >
    Export PDF
</button>
</div>
              <p className="text-sm text-slate-400">
                {data.hostname || "No reverse DNS"}
              </p>
              <div className="flex flex-wrap gap-4 mt-4">
                <div>
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest">
                    ASN
                  </p>
                  <p className="text-sm font-mono text-slate-200">
                    {cAsn}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest">
                    ISP
                  </p>
                  <p className="text-sm text-slate-200">
                    {abuseData?.isp || "—"}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest">
                    Country
                  </p>
                  <p className="text-sm text-slate-200">
                    {data.country} · {data.city}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] text-slate-500 uppercase tracking-widest">
                    Blacklists
                  </p>
                  <p
                    className={`text-sm font-semibold ${listedCount > 3 ? "text-red-400" : listedCount > 0 ? "text-amber-400" : "text-emerald-400"}`}
                  >
                    {listedCount} blacklist hits
                  </p>
                </div>
              </div>
            </div>
            {/* Gauge */}
            <div className="flex flex-col items-center lg:items-end gap-1">
              <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-1">
                Abuse Confidence
              </p>
              <RiskGauge score={score} />
            </div>
          </div>
        </div>
      )}

      {/* {summary} */}
      {data && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <SectionHeader title="Intelligence Summary" />

          <p className="text-sm text-slate-300 leading-7">{summary}</p>
        </div>
      )}

      {/* Quick stats grid */}
      {data && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard
            icon="⚑"
            label="Open Ports"
            value={cPorts.length ? `${cPorts.length} ports` : "—"}
            sub={cPorts.slice(0, 3).join(", ")}
            accent="bg-amber-500/10 text-amber-400"
          />
          <StatCard
            icon="⊗"
            label="Total Reports"
            value={
              abuseData?.totalReports ? String(abuseData.totalReports) : "—"
            }
            sub={`${abuseData?.numDistinctUsers ?? "—"} distinct users`}
            accent={
              abuseData?.totalReports > 50
                ? "bg-red-400/10 text-red-400"
                : "bg-slate-800 text-slate-400"
            }
          />
          <StatCard
            icon="⬡"
            label="CVEs Detected"
            value={
              Object.keys(cVulns).length > 0
                ? `${Object.keys(cVulns).length} CVEs`
                : "None"
            }
            sub={Object.keys(cVulns)[0]}
            accent={
              Object.keys(cVulns).length > 0
                ? "bg-red-400/10 text-red-400"
                : "bg-emerald-400/10 text-emerald-400"
            }
          />
          <StatCard
            icon="◎"
            label="Usage Type"
            value={abuseData?.usageType?.split("/")[0] || "—"}
            sub={abuseData?.domain}
            accent="bg-slate-800 text-slate-400"
          />
          {/* <StatCard
  icon="🛡"
  label="VT Malicious"
  value={
    virusTotalData?.data?.attributes?.last_analysis_stats?.malicious ?? 0
  }
  sub={`${
    virusTotalData?.data?.attributes?.last_analysis_stats?.suspicious ?? 0
  } suspicious`}
  accent={
    (virusTotalData?.data?.attributes?.last_analysis_stats?.malicious ?? 0) > 0
      ? "bg-red-400/10 text-red-400"
      : "bg-emerald-400/10 text-emerald-400"
  }
/> */}
        </div>
      )}

      {loading && <LoadingPulse />}
      {!data && !loading && (
        <EmptyState
          icon="⬡"
          title="Enter an IP address to begin analysis"
          sub="Supports IPv4 addresses. Results include threat intel, geolocation, and infrastructure data."
        />
      )}
    </div>
  );
}

function ThreatPanel({ abuseData, censysData, virusTotalData }) {
  if (!abuseData)
    return (
      <EmptyState
        icon="◈"
        title="No threat data loaded"
        sub="Run a search first"
      />
    );
  const score = abuseData.abuseConfidenceScore;
  const cfg = getRiskColor(score);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Score card */}
        <div className={`rounded-xl border p-5 ${cfg.bg} ${cfg.border}`}>
          <p className="text-[11px] uppercase tracking-widest text-slate-400 mb-3">
            Abuse Confidence Score
          </p>
          <div className="flex items-end gap-3 mb-4">
            <span className={`text-5xl font-bold tabular-nums ${cfg.text}`}>
              {score}
            </span>
            <span className="text-slate-500 text-lg pb-1">/ 100</span>
          </div>
          {/* Bar */}
          <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${score <= 20 ? "bg-emerald-400" : score <= 60 ? "bg-amber-400" : "bg-red-400"}`}
              style={{ width: `${score}%`, boxShadow: `0 0 8px ${cfg.ring}66` }}
            />
          </div>
          <div className="flex justify-between text-[10px] text-slate-600 mt-1">
            <span>0</span>
            <span>Safe</span>
            <span>Suspicious</span>
            <span>100</span>
          </div>
        </div>

        {/* Report stats */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <p className="text-[11px] uppercase tracking-widest text-slate-500">
            Report Statistics
          </p>
          {[
            ["Total Reports", abuseData.totalReports],
            ["Distinct Reporters", abuseData.numDistinctUsers],
            ["Last Reported", abuseData.lastReportedAt?.split("T")[0]],
            ["Whitelisted", abuseData.isWhitelisted ? "Yes" : "No"],
          ].map(([k, v]) => (
            <div
              key={k}
              className="flex justify-between items-center text-sm border-b border-slate-800/60 pb-2 last:border-0 last:pb-0"
            >
              <span className="text-slate-400 text-[13px]">{k}</span>
              <span
                className={`font-medium font-mono text-[13px] ${k === "Whitelisted" && v === "No" ? "text-red-400" : "text-slate-200"}`}
              >
                {v ?? "—"}
              </span>
            </div>
          ))}
        </div>
      </div>

      {virusTotalData && (
  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
    <SectionHeader title="Virus Total Analysis" />

    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <StatCard
        icon="☠"
        label="Malicious"
        value={
          virusTotalData?.data?.attributes?.last_analysis_stats?.malicious ?? 0
        }
        accent="bg-red-400/10 text-red-400"
      />

      <StatCard
        icon="⚠"
        label="Suspicious"
        value={
          virusTotalData?.data?.attributes?.last_analysis_stats?.suspicious ?? 0
        }
        accent="bg-amber-400/10 text-amber-400"
      />

      <StatCard
        icon="✓"
        label="Harmless"
        value={
          virusTotalData?.data?.attributes?.last_analysis_stats?.harmless ?? 0
        }
        accent="bg-emerald-400/10 text-emerald-400"
      />

      <StatCard
        icon="★"
        label="Reputation"
        value={
          virusTotalData?.data?.attributes?.reputation ?? 0
        }
        accent="bg-sky-500/10 text-sky-400"
      />
    </div>
  </div>
)}

      {/* Blacklist table */}
      {(abuseData || virusTotalData || censysData) && (() => {
        const blacklistData = {
          VirusTotal: (virusTotalData?.data?.attributes?.last_analysis_stats?.malicious ?? 0) > 0,
          AbuseIPDB: (abuseData?.abuseConfidenceScore ?? 0) > 50,
          Censys: Object.keys(censysData?.vulns || {}).length > 0,
        };
        return (
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
            <SectionHeader title="Blacklist Status" />
            <div className="space-y-2">
              {Object.entries(blacklistData).map(([name, listed]) => (
                <BlacklistRow key={name} name={name.toUpperCase()} listed={listed} />
              ))}
            </div>
          </div>
        );
      })()}

      {/* CVEs */}
      {Object.keys(censysData?.vulns || {}).length > 0 && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-5">
          <SectionHeader
            title="CVE Vulnerabilities"
            badge={`${Object.keys(censysData.vulns).length} DETECTED`}
          />
          <div className="space-y-2">
            {Object.keys(censysData.vulns).map((cve) => (
              <div
                key={cve}
                className="flex items-center justify-between py-2 border-b border-red-500/10 last:border-0"
              >
                <span className="font-mono text-[13px] text-red-300">
                  {cve}
                </span>
                <span className="text-[11px] text-red-500 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded">
                  Critical
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {virusTotalData?.data?.attributes?.tags?.length > 0 && (
  <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
    <SectionHeader title="VirusTotal Tags" />

    <div className="flex flex-wrap gap-2">
      {virusTotalData.data.attributes.tags.map((tag) => (
        <span
          key={tag}
          className="px-3 py-1 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20"
        >
          {tag}
        </span>
      ))}
    </div>
  </div>
)}
    </div>
  );
}

function InfraPanel({ censysData, data }) {
  if (!censysData)
    return (
      <EmptyState
        icon="◻"
        title="No infrastructure data loaded"
        sub="Run a search first"
      />
    );

  const org =
    censysData.org ||
    censysData.autonomous_system?.name ||
    censysData.autonomous_system?.description ||
    data?.org ||
    "—";
  const asn =
    censysData.asn ||
    (censysData.autonomous_system?.asn ? `AS${censysData.autonomous_system.asn}` : null) ||
    "—";
  const isp =
    censysData.isp ||
    censysData.autonomous_system?.description ||
    censysData.autonomous_system?.name ||
    "—";
  const os = censysData.os || "Unknown";
  const lastUpdate =
    censysData.last_update ||
    censysData.last_updated_at ||
    censysData.last_updated ||
    null;
  const lastUpdateDisplay = lastUpdate ? lastUpdate.split("T")[0] : "—";

  const hostnames =
    censysData.hostnames ||
    censysData.dns?.reverse_dns?.names ||
    [];
  const hostnamesDisplay = hostnames.length > 0 ? hostnames.join(", ") : "None";


  const ports =
    censysData.ports ||
    (censysData.services?.map((s) => s.port).filter(Boolean)) ||
    [];


    const tags = censysData.tags || censysData.labels || [];

  return (
    <div className="space-y-6">
      
      
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {[
          ["Organization", org],
          ["ASN", asn],
          ["ISP", isp],
          ["OS", os],
          ["Last Updated", lastUpdateDisplay],
          ["Hostnames", hostnamesDisplay],
        ].map(([k, v]) => (
          <div
            key={k}
            className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"
          >
            <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-1">
              {k}
            </p>
            <p
              className="text-sm text-slate-200 font-medium truncate"
              title={v}
            >
              {v || "—"}
            </p>
          </div>
        ))}
      </div>

      {/* Services detail (Censys-specific) */}
      {censysData.services?.length > 0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <SectionHeader
            title="Detected Services"
            badge={`${censysData.services.length} SERVICES`}
          />
          <div className="space-y-2">
            {censysData.services.map((svc, i) => (
              <div
                key={i}
                className="flex items-center justify-between py-2 border-b border-slate-800/60 last:border-0"
              >
                <div className="flex items-center gap-3">
                  <PortBadge port={svc.port} />
                  <span className="text-[13px] text-slate-300 font-mono">
                    {svc.service_name || svc.transport_protocol || "—"}
                  </span>
                </div>
                {svc.observed_at && (
                  <span className="text-[11px] text-slate-500">
                    {svc.observed_at.split("T")[0]}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Open Ports */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <SectionHeader
          title="Open Ports"
          badge={ports.length ? `${ports.length} DETECTED` : "0 DETECTED"}
        />
        <div className="flex flex-wrap gap-2">
          {ports.map((p, index) => (
  <PortBadge
    key={`${p}-${index}`}
    port={p}
  />
))}
          {!ports.length && (
            <span className="text-sm text-slate-500">
              No open ports detected
            </span>
          )}
        </div>
        <p className="text-[11px] text-slate-600 mt-3">
          {tags.includes("tor") &&
            "⚠ Tor exit node detected — traffic through this IP may be anonymized."}
        </p>
      </div>

      {/* Tags / Labels */}
      {tags.length > 0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <SectionHeader title="Censys Labels" />
          <div className="flex flex-wrap gap-2">
            {tags.map((t) => (
              <span
                key={t}
                className="text-[12px] font-mono px-3 py-1 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20"
              >
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Network activity bar chart */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <SectionHeader title="Port Activity Profile" />
        <div className="space-y-2 mt-2">
          {ports.length === 0 && (
            <p className="text-sm text-slate-500">No port data available</p>
          )}
          {ports.map((p, i) => {
            const pct = Math.max(20, 100 - i * 14);
            const isTor = [9001, 9030].includes(p);
            return (
              <div key={p} className="flex items-center gap-3">
                <span className="font-mono text-[11px] text-slate-500 w-10 text-right shrink-0">
                  {p}
                </span>
                <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${isTor ? "bg-purple-400" : "bg-sky-500"}`}
                    style={{
                      width: `${pct}%`,
                      boxShadow: isTor
                        ? "0 0 4px #a78bfa55"
                        : "0 0 4px #38bdf855",
                    }}
                  />
                </div>
                <span className="text-[11px] text-slate-600 w-8 tabular-nums">
                  {pct}%
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function GeoPanel({ data, lat, lng }) {
  if (!data)
    return (
      <EmptyState
        icon="◎"
        title="No geolocation data loaded"
        sub="Run a search first"
      />
    );
  const fields = [
    ["City", data.city],
    ["Region", data.region],
    ["Country", data.country],
    ["Coordinates", data.loc],
    ["Postal Code", data.postal || "—"],
    ["Timezone", data.timezone],
  ];
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {fields.map(([k, v]) => (
          <div
            key={k}
            className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"
          >
            <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-1">
              {k}
            </p>
            <p className="text-sm text-slate-200 font-medium font-mono">
              {v || "—"}
            </p>
          </div>
        ))}
      </div>
      {/* Map placeholder */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="p-4 border-b border-slate-800">
          <SectionHeader title="Geographic Location" />
        </div>
        <div
          className="relative flex items-center justify-center"
          style={{
            height: 280,
            background:
              "radial-gradient(ellipse at center, #0f172a 0%, #020617 100%)",
          }}
        >
          <MapContainer
            center={[lat, lng]}
            zoom={10}
            scrollWheelZoom={true}
            style={{
              height: "100%",
              width: "100%",
            }}
          >
            <TileLayer
              attribution="&copy; OpenStreetMap contributors"
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />

            <Marker position={[lat, lng]}>
              <Popup>
                {data.city}, {data.country}
              </Popup>
            </Marker>
          </MapContainer>
        </div>
      </div>
    </div>
  );
}

function HistoryPanel({ timeline }) {
  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <SectionHeader
          title="Event Timeline"
          badge={`${timeline.length} EVENTS`}
        />
        <div className="mt-2">
          {timeline.map((item, i) => (
            <TimelineItem
              key={i}
              item={item}
              last={i === timeline.length - 1}
            />
          ))}
        </div>
      </div>

    </div>
  );
}


function SearchBar({ ip, setIp, onSearch, loading, error, exportPDF }) {
  const handleKey = (e) => {
    if (e.key === "Enter") onSearch();
  };
  return (
    <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-20">
      <div className="flex gap-3 items-center max-w-2xl">
        <div className="relative flex-1">
          <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 text-sm">
            ⬡
          </span>
          <input
            type="text"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Enter IPv4 address to analyze…"
            className="w-full bg-slate-900 border border-slate-700 rounded-xl pl-9 pr-4 py-2.5 text-sm text-slate-200 placeholder-slate-600 outline-none focus:border-sky-500/60 focus:ring-1 focus:ring-sky-500/30 transition-all font-mono"
          />
        </div>
        <button
          onClick={onSearch}
          disabled={loading}
          className={`px-5 py-2.5 rounded-xl text-sm font-semibold transition-all duration-150 ${
            loading
              ? "bg-slate-800 text-slate-500 cursor-not-allowed"
              : "bg-sky-500 hover:bg-sky-400 active:scale-95 text-white shadow-lg shadow-sky-500/20"
          }`}
        >
          {loading ? (
            <span className="flex items-center gap-2">
              <span className="w-3.5 h-3.5 rounded-full border-2 border-sky-300/30 border-t-sky-300 animate-spin" />
              Analyzing
            </span>
          ) : (
            "Analyze →"
          )}
        </button>
      </div>
      {error && (
        <p className="text-red-400 text-xs mt-2 flex items-center gap-1.5">
          <span>⊗</span> {error}
        </p>
      )}
    </div>
  );
}



export default function App() {
  const [ip, setIp] = useState("");
  const [data, setData] = useState(null);
  const [lat, setLat] = useState(null);
  const [lng, setLng] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [abuseData, setAbuseData] = useState(null);
  const [censysData, setCensysData] = useState(null);
  const [virusTotalData, setVirusTotalData] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [searchHistory, setSearchHistory] = useState([]);
  // const [blacklistData, setBlacklistData] = useState(null);

  useEffect(() => {
    const savedHistory = localStorage.getItem("searchHistory");

    if (savedHistory) {
      setSearchHistory(JSON.parse(savedHistory));
    }
  }, []);

  const isValidIP = (v) =>
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(
      v,
    );

  const handleSearch = async (searchIp = ip) => {

    if (typeof searchIp !== "string") {
    searchIp = ip;
  }

    setError("");
  
    if (!searchIp.trim()) {
      setError("Please enter an IP address");
      setData(null);
      return;
    }
    if (!isValidIP(searchIp)) {
      setError("Invalid IPv4 address");
      setData(null);
      return;
    }
    try {
      setLoading(true);
      setData(null);
      setAbuseData(null);
      setCensysData(null);
      setVirusTotalData(null);
      
      const [
    ipData,
    abuseData,
    censysData,
    virusTotalData,
  ] = await Promise.all([
    fetchIpData(searchIp),
    fetchAbuseData(searchIp),
    fetchCensysData(searchIp),
    fetchVirusTotalData(searchIp),
  ]);
      setData(ipData);
      const coordinates = ipData?.loc?.split(",");
      setLat(Number(coordinates[0]));
      setLng(Number(coordinates[1]));
      setAbuseData(abuseData);
      setCensysData(
  censysData?.result?.resource || censysData
);
      console.log("CENSYS DATA:", censysData);
      setVirusTotalData(virusTotalData);

      const updatedHistory = [
        searchIp,
        ...searchHistory.filter((item) => item !== searchIp),
      ].slice(0, 4);
      setSearchHistory(updatedHistory);
      localStorage.setItem("searchHistory", JSON.stringify(updatedHistory));

      setActiveTab("overview");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const hasData = !!(data || abuseData || censysData || virusTotalData);

  const generateSummary = () => {
    if (!data || !abuseData) return "";

    const score = abuseData.abuseConfidenceScore;
    const risk = score <= 20 ? "LOW" : score <= 60 ? "MEDIUM" : "HIGH";
    const cPorts = censysData?.ports || censysData?.services?.map((s) => s.port).filter(Boolean) || [];
    const portCount = cPorts.length;
    const vulnCount = Object.keys(censysData?.vulns || {}).length;
    const vtMalicious =
  virusTotalData?.data?.attributes?.last_analysis_stats?.malicious ?? 0;

const vtReputation =
  virusTotalData?.data?.attributes?.reputation ?? 0;

    const isp = abuseData.isp ? ` via ${abuseData.isp}` : "";
    const vtSentence = vtMalicious > 0
      ? `VirusTotal flagged this IP as malicious by ${vtMalicious} security vendor${vtMalicious > 1 ? "s" : ""}, with a community reputation score of ${vtReputation}.`
      : `VirusTotal returned no malicious detections, with a reputation score of ${vtReputation}.`;
    const vulnSentence = vulnCount > 0
      ? `Censys identified ${vulnCount} known CVE vulnerability${vulnCount > 1 ? "ies" : ""} on this host.`
      : "No CVE vulnerabilities were detected by Censys.";
    const portSentence = portCount > 0
      ? `${portCount} open port${portCount > 1 ? "s" : ""} ${portCount > 1 ? "were" : "was"} found exposed.`
      : "No open ports were detected.";

    return `This IP address (${data.ip}) is geolocated to ${data.city}, ${data.country}${isp}. It carries an AbuseIPDB confidence score of ${score}/100 with ${abuseData.totalReports || 0} total reports from ${abuseData.numDistinctUsers || 0} distinct users. ${vtSentence} ${portSentence} ${vulnSentence} Based on aggregate signals across all three intelligence sources, the overall risk level is assessed as ${risk}.`;
  };

  const generateTimeline = () => {
  const timeline = [];


  const getLastUpdate = () =>
    censysData?.last_updated_at || censysData?.last_update || null;

  const cPorts = censysData?.ports || censysData?.services?.map((s) => s.port).filter(Boolean) || [];
  const cTags = censysData?.tags || censysData?.labels || [];
  const cves = Object.keys(censysData?.vulns || {});
  const lastUpdate = getLastUpdate();
  const vtMalicious =
  virusTotalData?.data?.attributes?.last_analysis_stats?.malicious ?? 0;

if (vtMalicious > 0) {
  timeline.push({
    date: new Date().toISOString().split("T")[0],
    event: `${vtMalicious} VirusTotal engines flagged this IP`,
    severity: vtMalicious > 10 ? "high" : "medium",
  });
}
  if (cves.length > 0) {
    timeline.push({
      date: lastUpdate?.split("T")[0],
      event: `${cves.length} vulnerabilities detected`,
      severity: "high",
    });
  }

  if (abuseData?.lastReportedAt) {
    timeline.push({
      date: abuseData.lastReportedAt.split("T")[0],
      event: "Last abuse report submitted",
      severity: abuseData.abuseConfidenceScore > 60 ? "high" : "medium",
    });
  }

  if (lastUpdate) {
    timeline.push({
      date: lastUpdate.split("T")[0],
      event: "Censys scan completed",
      severity: "low",
    });
  }

  if (cPorts.length > 0) {
    timeline.push({
      date: lastUpdate?.split("T")[0],
      event: `${cPorts.length} open ports detected`,
      severity: cPorts.length > 5 ? "high" : "medium",
    });
  }

  if (cTags.includes("tor")) {
    timeline.push({
      date: lastUpdate?.split("T")[0],
      event: "Tor exit node identified",
      severity: "high",
    });
  }

  if (abuseData?.abuseConfidenceScore >= 80) {
    timeline.push({
      date: abuseData.lastReportedAt?.split("T")[0],
      event: `High abuse score (${abuseData.abuseConfidenceScore}) recorded`,
      severity: "high",
    });
  }

  if (abuseData?.totalReports >= 100) {
    timeline.push({
      date: abuseData.lastReportedAt?.split("T")[0],
      event: `${abuseData.totalReports} abuse reports accumulated`,
      severity: "medium",
    });
  }

  if (lastUpdate) {
    timeline.push({
      date: lastUpdate.split("T")[0],
      event: "Observed by Censys",
      severity: "low",
    });
  }

  return timeline.sort((a, b) => new Date(b.date) - new Date(a.date));
};

  const exportPDF = () => {
  if (!data) return;

  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const pageW = doc.internal.pageSize.width;
  const pageH = doc.internal.pageSize.height;
  const margin = 14;
  const contentW = pageW - margin * 2;


  const COL = {
    navy:    [15,  23,  42],
    slate:   [30,  41,  59],
    slate2:  [51,  65,  85],
    white:   [255, 255, 255],
    sky:     [14, 165, 233],
    emerald: [52, 211, 153],
    amber:   [251, 191,  36],
    red:     [248, 113, 113],
    text:    [15,  23,  42],
    muted:   [100, 116, 139],
    border:  [203, 213, 225],
  };


  const abuseScore  = abuseData?.abuseConfidenceScore ?? 0;
  const vtStats     = virusTotalData?.data?.attributes?.last_analysis_stats ?? {};
  const vtMalicious = vtStats.malicious   ?? 0;
  const vtSuspicious= vtStats.suspicious  ?? 0;
  const vtHarmless  = vtStats.harmless    ?? 0;
  const vtUndetected= vtStats.undetected  ?? 0;
  const vtReputation= virusTotalData?.data?.attributes?.reputation ?? 0;
  const vtTags      = virusTotalData?.data?.attributes?.tags ?? [];
  const openPorts   = censysData?.ports || censysData?.services?.map((s) => s.port).filter(Boolean) || [];
  const services    = censysData?.services || [];
  const vulns       = Object.keys(censysData?.vulns || {});
  const cTags       = censysData?.tags || censysData?.labels || [];
  const org         = censysData?.autonomous_system?.name || censysData?.org || data?.org || "—";
  const asn         = censysData?.autonomous_system?.asn ? `AS${censysData.autonomous_system.asn}` : censysData?.asn || "—";
  const lastUpdated = (censysData?.last_updated_at || censysData?.last_update || "").split("T")[0] || "—";

  const risk       = abuseScore <= 20 ? "LOW" : abuseScore <= 60 ? "MEDIUM" : "HIGH";
  const riskColor  = risk === "HIGH" ? COL.red : risk === "MEDIUM" ? COL.amber : COL.emerald;
  const riskLabel  = risk === "HIGH" ? "HIGH RISK" : risk === "MEDIUM" ? "MEDIUM RISK" : "LOW RISK";

  const vtTotal    = vtMalicious + vtSuspicious + vtHarmless + vtUndetected;
  const vtOverall  = vtMalicious > 5 ? "MALICIOUS" : vtMalicious > 0 ? "SUSPICIOUS" : "CLEAN";


  const setFont = (size, style = "normal", color = COL.text) => {
    doc.setFontSize(size);
    doc.setFont("helvetica", style);
    doc.setTextColor(...color);
  };

  const sectionTitle = (label, y) => {
    doc.setFillColor(...COL.navy);
    doc.rect(margin, y, contentW, 7, "F");
    setFont(8, "bold", COL.white);
    doc.text(label.toUpperCase(), margin + 3, y + 5);
    return y + 12;
  };

  const pill = (label, x, y, bgColor, textColor = COL.white) => {
    const w = doc.getTextWidth(label) + 6;
    doc.setFillColor(...bgColor);
    doc.roundedRect(x, y - 4, w, 6, 1.5, 1.5, "F");
    setFont(7, "bold", textColor);
    doc.text(label, x + 3, y);
    return x + w + 3;
  };

  const addFooter = (pageNum, totalPages) => {
    const y = pageH - 10;
    doc.setFillColor(...COL.navy);
    doc.rect(0, y - 4, pageW, 14, "F");
    setFont(7, "normal", COL.muted);
    doc.text(`IP Intelligence Dashboard  ·  Confidential`, margin, y + 1);
    doc.text(`Generated: ${new Date().toLocaleString()}`, pageW / 2, y + 1, { align: "center" });
    doc.text(`Page ${pageNum} of ${totalPages}`, pageW - margin, y + 1, { align: "right" });
  };

  
  doc.setFillColor(...COL.navy);
  doc.rect(0, 0, pageW, 52, "F");


  doc.setFillColor(...COL.sky);
  doc.rect(0, 52, pageW, 2, "F");



  setFont(22, "bold", COL.white);
  doc.text("IP Intelligence Report", margin, 22);
  setFont(10, "normal", [148, 163, 184]);
  doc.text("Threat Analysis  ·  Infrastructure  ·  Geolocation", margin, 31);


  setFont(16, "bold", COL.sky);
  doc.text(data.ip, margin, 45);


  doc.setFillColor(...riskColor);
  doc.roundedRect(pageW - margin - 38, 10, 38, 16, 2, 2, "F");
  setFont(9, "bold", COL.white);
  doc.text(riskLabel, pageW - margin - 19, 20, { align: "center" });
  setFont(7, "normal", COL.white);
  doc.text(`Score: ${abuseScore}/100`, pageW - margin - 19, 25, { align: "center" });

  let y = 62;

  const kpis = [
    { label: "Abuse Score",    value: `${abuseScore}/100`, color: riskColor },
    { label: "VT Detections",  value: `${vtMalicious} malicious`, color: vtMalicious > 0 ? COL.red : COL.emerald },
    { label: "Open Ports",     value: String(openPorts.length), color: COL.sky },
    { label: "CVEs Detected",  value: String(vulns.length), color: vulns.length > 0 ? COL.red : COL.emerald },
  ];
  const kpiW = contentW / kpis.length;
  kpis.forEach((k, i) => {
    const x = margin + i * kpiW;
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(...COL.border);
    doc.rect(x, y, kpiW - 2, 22, "FD");
    setFont(7, "normal", COL.muted);
    doc.text(k.label.toUpperCase(), x + 4, y + 7);
    setFont(14, "bold", k.color);
    doc.text(String(k.value), x + 4, y + 18);
  });
  y += 30;


  y = sectionTitle("Executive Summary", y);

  const isp = abuseData?.isp ? ` via ${abuseData.isp}` : "";
  const summaryText =
    `This report documents the threat intelligence analysis of IP address ${data.ip}, geolocated to ${data.city}, ${data.region}, ${data.country}${isp}. ` +
    `The host is registered under ASN ${asn} (${org}) and classified as "${abuseData?.usageType || "Unknown"}" usage type. ` +
    `\n\n` +
    `AbuseIPDB assigns this address a confidence score of ${abuseScore}/100, derived from ${abuseData?.totalReports || 0} abuse reports submitted by ${abuseData?.numDistinctUsers || 0} distinct users. ` +
    (abuseData?.lastReportedAt ? `The most recent report was filed on ${abuseData.lastReportedAt.split("T")[0]}. ` : "") +
    `\n\n` +
    (vtTotal > 0
      ? `VirusTotal analysis across ${vtTotal} security engines returned ${vtMalicious} malicious, ${vtSuspicious} suspicious, and ${vtHarmless} harmless verdicts, yielding a community reputation score of ${vtReputation}. `
      : `VirusTotal returned no engine results for this address. `) +
    `\n\n` +
    `Censys infrastructure scanning detected ${openPorts.length} open port${openPorts.length !== 1 ? "s" : ""} and ${vulns.length} known CVE vulnerability${vulns.length !== 1 ? "ies" : ""}. ` +
    (cTags.includes("tor") ? "This host is identified as a Tor exit node. " : "") +
    `\n\n` +
    `Based on the aggregate signals above, the overall risk classification for this address is ${risk}. ` +
    (risk === "HIGH"
      ? "Immediate action is recommended — consider blocking this IP at the perimeter and investigating any prior connections."
      : risk === "MEDIUM"
      ? "This address warrants active monitoring. Review firewall logs for any interaction with internal systems."
      : "No significant threat indicators were detected. Continued passive monitoring is advised.");

  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(...COL.border);

  const splitSummary = doc.splitTextToSize(summaryText, contentW - 8);
  const summaryH = splitSummary.length * 4.5 + 8;
  doc.rect(margin, y, contentW, summaryH, "FD");
  setFont(9.5, "normal", COL.text);
  doc.text(splitSummary, margin + 4, y + 6);
  y += summaryH + 8;


  y = sectionTitle("Host Identification", y);

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    columnStyles: { 0: { cellWidth: 45, fontStyle: "bold", fillColor: [248, 250, 252] }, 1: { cellWidth: contentW - 45 } },
    styles: { fontSize: 9, cellPadding: 3, lineColor: COL.border, lineWidth: 0.2 },
    headStyles: { fillColor: COL.slate, textColor: COL.white, fontSize: 8 },
    body: [
      ["IP Address",   data.ip],
      ["Hostname",     data.hostname || "No reverse DNS"],
      ["Country",      `${data.country} (${data.countryCode || ""})`],
      ["Region / City",`${data.region} / ${data.city}`],
      ["Coordinates",  data.loc || "—"],
      ["Timezone",     data.timezone || "—"],
      ["Postal Code",  data.postal || "—"],
      ["Organization", org],
      ["ASN",          asn],
      ["ISP",          abuseData?.isp || "—"],
      ["Domain",       abuseData?.domain || "—"],
      ["Usage Type",   abuseData?.usageType || "—"],
      ["Whitelisted",  abuseData?.isWhitelisted ? "Yes" : "No"],
      ["Last Updated (Censys)", lastUpdated],
    ],
  });

  addFooter(1, 3);



  doc.addPage();


  doc.setFillColor(...COL.navy);
  doc.rect(0, 0, pageW, 14, "F");
  setFont(10, "bold", COL.white);
  doc.text("Threat Intelligence Analysis", margin, 9);
  setFont(8, "normal", [148, 163, 184]);
  doc.text(data.ip, pageW - margin, 9, { align: "right" });

  y = 20;


  y = sectionTitle("AbuseIPDB Analysis", y);


  const barX = margin, barY = y, barH = 8, barW = contentW;
  doc.setFillColor(226, 232, 240);
  doc.roundedRect(barX, barY, barW, barH, 2, 2, "F");
  const fillW = Math.max(2, (abuseScore / 100) * barW);
  doc.setFillColor(...riskColor);
  doc.roundedRect(barX, barY, fillW, barH, 2, 2, "F");
  setFont(7, "bold", COL.white);
  if (fillW > 14) doc.text(`${abuseScore}%`, barX + fillW - 10, barY + 5.5);
  y += 12;

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    columnStyles: { 0: { cellWidth: 55, fontStyle: "bold", fillColor: [248, 250, 252] } },
    styles: { fontSize: 9, cellPadding: 3, lineColor: COL.border, lineWidth: 0.2 },
    body: [
      ["Confidence Score",   `${abuseScore} / 100  (${riskLabel})`],
      ["Total Reports",      String(abuseData?.totalReports || 0)],
      ["Distinct Reporters", String(abuseData?.numDistinctUsers || 0)],
      ["Last Reported",      abuseData?.lastReportedAt?.split("T")[0] || "—"],
      ["Whitelisted",        abuseData?.isWhitelisted ? "Yes" : "No"],
      ["Country Code",       abuseData?.countryCode || "—"],
    ],
  });
  y = doc.lastAutoTable.finalY + 10;



  y = sectionTitle("VirusTotal Analysis", y);

  if (vtTotal > 0) {
    const segments = [
      { count: vtMalicious,  color: COL.red,     label: `Malicious (${vtMalicious})` },
      { count: vtSuspicious, color: COL.amber,   label: `Suspicious (${vtSuspicious})` },
      { count: vtHarmless,   color: COL.emerald, label: `Harmless (${vtHarmless})` },
      { count: vtUndetected, color: COL.border,  label: `Undetected (${vtUndetected})` },
    ];
    let bx = margin;
    const bh = 7, bw = contentW;
    segments.forEach(({ count, color }) => {
      if (count <= 0) return;
      const sw = (count / vtTotal) * bw;
      doc.setFillColor(...color);
      doc.rect(bx, y, sw, bh, "F");
      bx += sw;
    });
    y += 10;

    let lx = margin;
    segments.forEach(({ color, label }) => {
      doc.setFillColor(...color);
      doc.rect(lx, y, 3, 3, "F");
      setFont(7, "normal", COL.muted);
      doc.text(label, lx + 5, y + 2.5);
      lx += doc.getTextWidth(label) + 10;
    });
    y += 8;
  }

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    columnStyles: { 0: { cellWidth: 55, fontStyle: "bold", fillColor: [248, 250, 252] } },
    styles: { fontSize: 9, cellPadding: 3, lineColor: COL.border, lineWidth: 0.2 },
    body: [
      ["Overall Verdict",    vtOverall],
      ["Malicious Engines",  String(vtMalicious)],
      ["Suspicious Engines", String(vtSuspicious)],
      ["Harmless Engines",   String(vtHarmless)],
      ["Undetected",         String(vtUndetected)],
      ["Total Engines",      String(vtTotal)],
      ["Reputation Score",   String(vtReputation)],
      ["Tags",               vtTags.length > 0 ? vtTags.join(", ") : "None"],
    ],
  });
  y = doc.lastAutoTable.finalY + 10;


  y = sectionTitle("Blacklist / Blocklist Status", y);

  const blacklistRows = [
    ["VirusTotal",  vtMalicious > 0 ? "LISTED" : "CLEAN",  vtMalicious > 0],
    ["AbuseIPDB",   abuseScore > 50  ? "FLAGGED" : "CLEAN", abuseScore > 50],
    ["Censys CVEs", vulns.length > 0 ? "VULNERABILITIES DETECTED" : "CLEAN", vulns.length > 0],
  ];

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    head: [["Source", "Status", "Detail"]],
    headStyles: { fillColor: COL.slate, textColor: COL.white, fontSize: 8 },
    columnStyles: {
      0: { cellWidth: 50 },
      1: { cellWidth: 45, fontStyle: "bold" },
      2: { cellWidth: contentW - 95 },
    },
    styles: { fontSize: 9, cellPadding: 3, lineColor: COL.border, lineWidth: 0.2 },
    body: blacklistRows.map(([source, status, flagged]) => [
      source,
      status,
      flagged
        ? (source === "VirusTotal"
            ? `${vtMalicious} engines detected malicious activity`
            : source === "AbuseIPDB"
            ? `Confidence score ${abuseScore}/100 exceeds threshold`
            : `${vulns.length} CVE(s) detected on exposed services`)
        : "No indicators of compromise",
    ]),
    didParseCell(data) {
      if (data.column.index === 1 && data.section === "body") {
        const flagged = blacklistRows[data.row.index]?.[2];
        data.cell.styles.textColor = flagged ? [239, 68, 68] : [16, 185, 129];
      }
    },
  });

  addFooter(2, 3);



  doc.addPage();

  doc.setFillColor(...COL.navy);
  doc.rect(0, 0, pageW, 14, "F");
  setFont(10, "bold", COL.white);
  doc.text("Infrastructure & Recommendations", margin, 9);
  setFont(8, "normal", [148, 163, 184]);
  doc.text(data.ip, pageW - margin, 9, { align: "right" });

  y = 20;

  y = sectionTitle("Open Ports & Exposed Services", y);

  if (services.length > 0) {
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [["Port", "Protocol", "Service", "Last Observed"]],
      headStyles: { fillColor: COL.slate, textColor: COL.white, fontSize: 8 },
      columnStyles: {
        0: { cellWidth: 22 },
        1: { cellWidth: 28 },
        2: { cellWidth: 70 },
        3: { cellWidth: contentW - 120 },
      },
      styles: { fontSize: 8.5, cellPadding: 2.5, lineColor: COL.border, lineWidth: 0.2 },
      body: services.map((svc) => [
        String(svc.port || "—"),
        (svc.transport_protocol || "—").toUpperCase(),
        svc.service_name || svc.extended_service_name || "—",
        svc.observed_at?.split("T")[0] || "—",
      ]),
    });
  } else if (openPorts.length > 0) {
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [["Port", "Classification"]],
      headStyles: { fillColor: COL.slate, textColor: COL.white, fontSize: 8 },
      styles: { fontSize: 9, cellPadding: 3, lineColor: COL.border, lineWidth: 0.2 },
      body: openPorts.map((p) => {
        const known = { 22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 9001: "Tor", 9030: "Tor Directory", 21: "FTP", 25: "SMTP", 53: "DNS", 3306: "MySQL", 5432: "PostgreSQL" };
        return [String(p), known[p] || "Unknown / Non-standard"];
      }),
    });
  } else {
    setFont(9, "normal", COL.muted);
    doc.text("No open ports detected.", margin, y + 5);
    y += 12;
  }

  y = doc.lastAutoTable?.finalY + 10 || y + 10;


  y = sectionTitle("CVE Vulnerabilities", y);

  if (vulns.length > 0) {
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [["CVE Identifier", "Severity"]],
      headStyles: { fillColor: [127, 29, 29], textColor: COL.white, fontSize: 8 },
      columnStyles: { 0: { cellWidth: 80 }, 1: { cellWidth: contentW - 80, fontStyle: "bold" } },
      styles: { fontSize: 9, cellPadding: 3, lineColor: COL.border, lineWidth: 0.2 },
      body: vulns.map((cve) => [cve, "Critical"]),
      didParseCell(data) {
        if (data.column.index === 1 && data.section === "body") {
          data.cell.styles.textColor = COL.red;
        }
      },
    });
    y = doc.lastAutoTable.finalY + 10;
  } else {
    setFont(9, "normal", COL.muted);
    doc.text("No CVE vulnerabilities were detected on this host.", margin, y + 5);
    y += 14;
  }


  if (cTags.length > 0) {
    y = sectionTitle("Censys Labels / Tags", y);
    let lx = margin;
    cTags.forEach((tag) => {
      lx = pill(tag.toUpperCase(), lx, y + 4, COL.slate2);
    });
    y += 14;
  }


  y = sectionTitle("Analyst Recommendations", y);

  const recommendations = [];
  if (risk === "HIGH") {
    recommendations.push("IMMEDIATE: Block this IP at the network perimeter (firewall / WAF) and review all historical connections from internal systems.");
    recommendations.push("INVESTIGATE: Audit logs for any data exfiltration, lateral movement, or command-and-control activity originating from or destined to this address.");
  }
  if (risk === "MEDIUM" || risk === "HIGH") {
    recommendations.push("MONITOR: Add this IP to your SIEM watchlist and configure alerts for any future connection attempts.");
  }
  if (vulns.length > 0) {
    recommendations.push(`PATCH: ${vulns.length} CVE(s) detected on exposed services. Review each CVE and apply vendor patches or mitigations immediately.`);
  }
  if (openPorts.some((p) => [21, 23, 3306, 5432, 6379, 27017].includes(p))) {
    recommendations.push("HARDEN: Sensitive service ports (database, FTP, Telnet) are exposed. Restrict access using firewall rules to trusted IPs only.");
  }
  if (cTags.includes("tor")) {
    recommendations.push("TOR NODE: This IP is a known Tor exit node. All traffic through it is anonymized. Block if anonymous access is not an expected use case.");
  }
  if (vtMalicious > 0) {
    recommendations.push(`THREAT INTEL: ${vtMalicious} VirusTotal engine(s) have flagged this IP. Cross-reference with your EDR and threat feeds for corroboration.`);
  }
  if (recommendations.length === 0) {
    recommendations.push("No immediate action required. Maintain standard passive monitoring of this address in accordance with your security policy.");
  }

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    columnStyles: {
      0: { cellWidth: 28, fontStyle: "bold", fillColor: [248, 250, 252] },
      1: { cellWidth: contentW - 28 },
    },
    styles: { fontSize: 9, cellPadding: 4, lineColor: COL.border, lineWidth: 0.2 },
    body: recommendations.map((rec, i) => [`#${i + 1}`, rec]),
  });

  y = doc.lastAutoTable.finalY + 10;


  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(...COL.border);
  doc.rect(margin, y, contentW, 18, "FD");
  setFont(7.5, "bold", COL.muted);
  doc.text("DISCLAIMER", margin + 3, y + 5);
  setFont(7.5, "normal", COL.muted);
  const disclaimer = "This report is generated automatically from third-party threat intelligence feeds (AbuseIPDB, VirusTotal, Censys). Data accuracy is subject to the freshness and coverage of each provider. This report does not constitute legal advice. Always conduct independent verification before taking action against any IP address.";
  doc.text(doc.splitTextToSize(disclaimer, contentW - 6), margin + 3, y + 10);

  addFooter(3, 3);

  doc.save(`Threat_Report_${data.ip}_${new Date().toISOString().split("T")[0]}.pdf`);
};

  return (
    <div
      className="flex h-screen bg-slate-950 text-white overflow-hidden"
      style={{ fontFamily: "'DM Sans', system-ui, sans-serif" }}
    >
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }
        * { box-sizing: border-box; }
      `}</style>

      <Sidebar
        active={activeTab}
        onChange={setActiveTab}
        hasData={hasData}
        searchHistory={searchHistory}
        onHistoryClick={(selectedIp) => {
  setIp(selectedIp);
  handleSearch(selectedIp);
}}

      />

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <SearchBar
          ip={ip}
          setIp={setIp}
          onSearch={handleSearch}
          loading={loading}
          error={error}
          exportPDF={exportPDF}
        />

        <main className="flex-1 overflow-y-auto px-6 py-6">
          <div className="max-w-4xl mx-auto">
            {activeTab === "overview" && (
              <OverviewPanel
                ip={ip}
                data={data}
                abuseData={abuseData}
                censysData={censysData}
                virusTotalData={virusTotalData}
                loading={loading}
                summary={generateSummary()}
                exportPDF={exportPDF}
              />
            )}
            {activeTab === "threat" && (
              <ThreatPanel 
                abuseData={abuseData} 
                censysData={censysData} 
                virusTotalData={virusTotalData} 
              />
            )}
            {activeTab === "infra" && (
              <InfraPanel censysData={censysData} data={data} />
            )}
            {activeTab === "geo" && (
              <GeoPanel data={data} lat={lat} lng={lng} />
            )}
            {activeTab === "history" && (
  <HistoryPanel timeline={generateTimeline()} />
)}
          </div>
        </main>
      </div>
    </div>
  );
}