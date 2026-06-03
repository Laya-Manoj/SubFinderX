const ADMIN_KEYWORDS = [
  "admin",
  "login",
  "signin",
  "sign-in",
  "auth",
  "dashboard",
  "portal",
  "cpanel",
  "manage",
  "wp-admin",
];

const DEV_KEYWORDS = [
  "dev",
  "staging",
  "stage",
  "test",
  "uat",
  "qa",
  "sandbox",
  "preview",
  "beta",
  "demo",
];

const LOGIN_TITLE_KEYWORDS = [
  "login",
  "log in",
  "sign in",
  "signin",
  "authentication",
  "authenticate",
  "sso",
  "password",
  "portal access",
];

const WARN_PHRASES = [
  "administrative",
  "development or staging",
  "missing important browser",
  "misconfigured",
];

function isLive(item) {
  return item.status_label === "active" || item.is_live;
}

function observationLevel(observations) {
  const text = observations.join(" ").toLowerCase();
  if (WARN_PHRASES.some((phrase) => text.includes(phrase))) {
    return "warn";
  }
  if (observations.length) {
    return "info";
  }
  return "neutral";
}

export function getSecurityObservation(item) {
  if (item.security_observation) {
    return {
      text: item.security_observation,
      level: item.security_observation_level || "neutral",
    };
  }

  if (item.status_label === "unverified") {
    return {
      text: "Host discovered; HTTP response not yet confirmed.",
      level: "neutral",
    };
  }

  if (!isLive(item)) {
    return {
      text: "Host discovered but currently unresponsive.",
      level: "neutral",
    };
  }

  const name = String(item.name || "").toLowerCase();
  const title = String(item.title || "").toLowerCase();
  const missing = item.security_headers?.missing_headers || [];
  const ports = new Set((item.open_ports || []).map((p) => Number(p)));
  const observations = [];

  if (
    ADMIN_KEYWORDS.some((keyword) => name.includes(keyword)) ||
    LOGIN_TITLE_KEYWORDS.some((keyword) => title.includes(keyword))
  ) {
    observations.push("Potential administrative interface detected.");
  }

  if (DEV_KEYWORDS.some((keyword) => name.includes(keyword))) {
    observations.push("Possible development or staging environment exposed.");
  }

  if (missing.length >= 2) {
    observations.push("Missing important browser security protections.");
  }

  if (ports.has(80) && ports.has(443)) {
    observations.push("Public web service exposed over HTTP/HTTPS.");
  }

  const status = Number(item.status);
  if (!Number.isNaN(status)) {
    if (status >= 500) {
      observations.push("Server returned an error response; service may be misconfigured.");
    } else if (status === 401 || status === 403) {
      observations.push("Access-restricted page detected.");
    }
  }

  if (!observations.length) {
    return {
      text: "No major exposure indicators detected.",
      level: "neutral",
    };
  }

  return {
    text: observations.join(" "),
    level: observationLevel(observations),
  };
}

export function observationClassName(level) {
  if (level === "warn") return "security-observation security-observation-warn";
  if (level === "info") return "security-observation security-observation-info";
  return "security-observation";
}
