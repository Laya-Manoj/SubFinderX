function StatusBadge({ label }) {
  const normalized = (label || "inactive").toLowerCase();
  const className =
    normalized === "active"
      ? "badge badge-live"
      : normalized === "unverified"
        ? "badge badge-unverified"
        : "badge badge-inactive";
  const text =
    normalized === "active" ? "Live" : normalized === "unverified" ? "Unverified" : "Inactive";
  return <span className={className}>{text}</span>;
}

function ResultsTable({ data }) {
  const rows = data.subdomains || [];
  const liveRows = rows.filter((item) => item.status_label === "active" || item.is_live);
  const unverifiedRows = rows.filter((item) => item.status_label === "unverified");
  const inactiveRows = rows.filter(
    (item) =>
      item.status_label === "inactive" ||
      (!item.is_live && item.status_label !== "unverified" && item.status_label !== "active")
  );

  const statusClassName = (status) => {
    if (status >= 200 && status < 300) return "status-good";
    if (status >= 300 && status < 400) return "status-warn";
    if (status >= 400) return "status-bad";
    return "";
  };

  const getHostUrl = (item) => {
    const protocol = item.protocol || (item.open_ports?.includes(443) ? "https" : "http");
    return `${protocol}://${item.name}`;
  };

  return (
    <div className="tables">
      <div className="table-block">
        <h3>Live Subdomains</h3>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Subdomain</th>
                <th>Status</th>
                <th>Title</th>
                <th>Ports</th>
                <th>Missing Security Headers</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {liveRows.map((item) => (
                <tr key={item.name}>
                  <td>
                    <a className="subdomain-link" href={getHostUrl(item)} target="_blank" rel="noreferrer">
                      {item.name}
                    </a>
                  </td>
                  <td>
                    <StatusBadge label="active" />
                    <span className={`status-code ${statusClassName(item.status)}`}>
                      {item.status || "-"}
                    </span>
                  </td>
                  <td>{item.title || "-"}</td>
                  <td>{item.open_ports?.length ? item.open_ports.join(", ") : "-"}</td>
                  <td className="missing-headers">
                    {item.security_headers?.missing_headers?.length
                      ? item.security_headers.missing_headers.join(", ")
                      : "None"}
                  </td>
                  <td>{item.source?.join(", ") || "-"}</td>
                </tr>
              ))}
              {!liveRows.length ? (
                <tr>
                  <td colSpan={6}>No live hosts</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="table-block">
        <h3>Unverified Subdomains</h3>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Subdomain</th>
                <th>Status</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {unverifiedRows.map((item) => (
                <tr key={item.name}>
                  <td>{item.name}</td>
                  <td>
                    <StatusBadge label="unverified" />
                  </td>
                  <td>{item.source?.join(", ") || "-"}</td>
                </tr>
              ))}
              {!unverifiedRows.length ? (
                <tr>
                  <td colSpan={3}>None</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="table-block">
        <h3>Inactive Subdomains</h3>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Subdomain</th>
                <th>Status</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {inactiveRows.map((item) => (
                <tr key={item.name}>
                  <td>{item.name}</td>
                  <td>
                    <StatusBadge label="inactive" />
                    <span className={statusClassName(item.status)}>
                      {item.status || "No HTTP response"}
                    </span>
                  </td>
                  <td>{item.source?.join(", ") || "-"}</td>
                </tr>
              ))}
              {!inactiveRows.length ? (
                <tr>
                  <td colSpan={3}>None</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="table-block">
        <h3>Classified Subdomains</h3>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Category</th>
                <th>Subdomains</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(data.classified || {}).map(([category, hosts]) => (
                <tr key={category}>
                  <td>{category}</td>
                  <td>{hosts.length ? hosts.join(", ") : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default ResultsTable;
