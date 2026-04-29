function ResultsTable({ data }) {
  const liveRows = data.live_subdomains || [];
  const inactiveRows = (data.subdomains || []).filter((item) => !item.is_live);

  const statusClassName = (status) => {
    if (status >= 200 && status < 300) return "status-good";
    if (status >= 300 && status < 400) return "status-warn";
    if (status >= 400) return "status-bad";
    return "";
  };

  const getHostUrl = (item) => {
    const ports = item.open_ports || [];
    const scheme = ports.includes(443) ? "https" : "http";
    return `${scheme}://${item.name}`;
  };

  return (
    <div className="tables">
      <h3>Live Subdomains</h3>
      <table>
        <thead>
          <tr>
            <th>Subdomain</th>
            <th>Status</th>
            <th>Title</th>
            <th>Ports</th>
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
              <td className={statusClassName(item.status)}>{item.status || "-"}</td>
              <td>{item.title || "-"}</td>
              <td>{item.open_ports.length ? item.open_ports.join(", ") : "-"}</td>
              <td>{item.source?.join(", ") || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Inactive / Unresponsive</h3>
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
              <td className={statusClassName(item.status)}>{item.status || "No HTTP response"}</td>
              <td>{item.source?.join(", ") || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Classified Subdomains</h3>
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Subdomains</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(data.classified).map(([category, hosts]) => (
            <tr key={category}>
              <td>{category}</td>
              <td>{hosts.length ? hosts.join(", ") : "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default ResultsTable;
