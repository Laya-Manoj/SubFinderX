import Charts from "./Charts";
import ResultsTable from "./ResultsTable";

function Dashboard({ data }) {
  const liveCount = data.live_subdomains.length;
  const deadCount = data.dead_subdomains.length;

  const downloadReport = (format = "json") => {
    window.open(`http://127.0.0.1:5000/report/${data.report_id}?format=${format}`, "_blank");
  };

  return (
    <section className="dashboard">
      <article className="flat-panel fade-in">
        <h2>Target: {data.domain}</h2>
        <div className="actions">
          <button onClick={() => downloadReport("json")}>Download JSON Report</button>
          <button onClick={() => downloadReport("html")}>Download HTML Report</button>
        </div>
      </article>

      <section className="summary-grid fade-in">
        <article className="counter total">
          <h3>Total Subdomains</h3>
          <p className="summary-value">{data.total_subdomains}</p>
        </article>
        <article className="counter live">
          <h3>Live</h3>
          <p className="summary-value">{liveCount}</p>
        </article>
        <article className="counter dead">
          <h3>Dead</h3>
          <p className="summary-value">{deadCount}</p>
        </article>
      </section>

      <article className="flat-panel fade-in">
        <h2>Enumeration Summary</h2>
        <p><strong>Passive count:</strong> {data.passive_count}</p>
        <p><strong>Brute-force count:</strong> {data.brute_force_count}</p>
        <p><strong>Wordlist entries:</strong> {data.wordlist?.combined_entries ?? 0}</p>
        <p><strong>Security analysis coverage:</strong> {data.analyzed_live_subdomains ?? 0} live hosts</p>
        <p><strong>Scan mode:</strong> {data.scan_mode === "full" ? "Full Scan" : "Quick Scan"}</p>
      </article>

      <article className="flat-panel fade-in">
        <h2>Charts</h2>
        <Charts liveCount={liveCount} deadCount={deadCount} statusCodes={data.status_codes} />
      </article>

      <article className="flat-panel fade-in">
        <h2>Results Table</h2>
        <ResultsTable data={data} />
      </article>
    </section>
  );
}

export default Dashboard;
