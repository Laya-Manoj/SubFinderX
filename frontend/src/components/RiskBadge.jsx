function RiskBadge({ level }) {
  const normalized = (level || "N/A").toLowerCase();
  let className = "badge badge-risk-na";
  let text = "N/A";

  if (normalized === "high") {
    className = "badge badge-risk-high";
    text = "High";
  } else if (normalized === "medium") {
    className = "badge badge-risk-medium";
    text = "Medium";
  } else if (normalized === "low") {
    className = "badge badge-risk-low";
    text = "Low";
  }

  return <span className={className}>{text}</span>;
}

export default RiskBadge;
