const PRIMARY_KEYWORDS = ["admin", "api", "dev", "staging", "internal", "test"];
const HIGH_RISK_KEYWORDS = ["admin", "dev", "staging", "internal"];
const UNUSUAL_PORTS = new Set([21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5432, 6379, 8080, 8443]);

function isHttpAccessible(item, status) {
  if (item.is_live || item.status_label === "active") return true;
  return !Number.isNaN(status) && status >= 200 && status < 400;
}

export function getRiskLevel(item) {
  if (item.risk_level && item.risk_level !== "N/A") {
    return item.risk_level;
  }

  const name = String(item.name || "").toLowerCase();
  const missing = item.security_headers?.missing_headers || [];
  const ports = (item.open_ports || []).map((p) => Number(p)).filter((p) => !Number.isNaN(p));
  const status = Number(item.status);
  const missingCount = missing.length;
  const portCount = ports.length;
  const sensitive = PRIMARY_KEYWORDS.some((k) => name.includes(k));
  const highKeyword = HIGH_RISK_KEYWORDS.some((k) => name.includes(k));
  const unusualPort = ports.some((p) => UNUSUAL_PORTS.has(p));
  const httpAccessible = isHttpAccessible(item, status);

  if (highKeyword && missingCount >= 2 && portCount >= 2) {
    return "High";
  }
  if (highKeyword && missingCount >= 2) {
    return "High";
  }
  if (sensitive && missingCount >= 2 && (portCount >= 2 || unusualPort)) {
    return "High";
  }
  if (missingCount >= 3) {
    return "Medium";
  }
  if (sensitive && missingCount >= 1) {
    return "Medium";
  }
  if (portCount >= 2 || unusualPort) {
    return "Medium";
  }
  if (httpAccessible && missingCount >= 2) {
    return "Medium";
  }
  return "Low";
}

export function getRiskSummary(data) {
  if (data.risk_summary) {
    return data.risk_summary;
  }
  const summary = { high: 0, medium: 0, low: 0 };
  for (const item of data.subdomains || []) {
    if (item.status_label !== "active" && !item.is_live) continue;
    const level = getRiskLevel(item).toLowerCase();
    if (summary[level] !== undefined) {
      summary[level] += 1;
    }
  }
  return summary;
}
