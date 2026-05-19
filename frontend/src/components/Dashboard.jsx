import Charts from "./Charts";
import ResultsTable from "./ResultsTable";

function Dashboard({ data }) {
  const summary = data.scan_summary || {};
  const liveCount = summary.live ?? data.live_subdomains?.length ?? 0;
  const inactiveCount =
    summary.inactive ??
    (data.subdomains || []).filter((item) => item.status_label === "inactive").length;
  const unverifiedCount =
    summary.unverified ?? data.unverified_subdomains?.length ?? 0;
  const totalCount = summary.total ?? data.total_subdomains ?? 0;
  const openPortsCount =
    summary.open_ports_found ??
    (data.subdomains || []).reduce(
      (acc, item) => acc + (item.open_ports?.length || 0),
      0
    );

  const downloadReport = (format = "json") => {
    window.open(
      `http://127.0.0.1:5000/report/${data.report_id}?format=${format}`,
      "_blank"
    );
  };

  return (
    <section className="dashboard">
      <article className="flat-panel fade-in">
        <h2>Target: {data.domain}</h2>
        {data.quick_scan_note ? <p className="scan-note">{data.quick_scan_note}</p> : null}
        <div className="actions">
          <button type="button" onClick={() => downloadReport("json")}>
            Download JSON Report
          </button>
          <button type="button" onClick={() => downloadReport("html")}>
            Download HTML Report
          </button>
          <button type="button" onClick={() => downloadReport("pdf")}>
            Download PDF Report
          </button>
        </div>
      </article>

      <section className="summary-grid fade-in">
        <article className="counter total">
          <h3>Total Subdomains</h3>
          <p className="summary-value">{totalCount}</p>
        </article>
        <article className="counter live">
          <h3>Live Hosts</h3>
          <p className="summary-value">{liveCount}</p>
        </article>
        <article className="counter dead">
          <h3>Inactive Hosts</h3>
          <p className="summary-value">{inactiveCount}</p>
        </article>
        <article className="counter ports">
          <h3>Open Ports Found</h3>
          <p className="summary-value">{openPortsCount}</p>
        </article>
      </section>

      {unverifiedCount > 0 ? (
        <article className="flat-panel fade-in summary-unverified">
          <p>
            <span className="badge badge-unverified">Unverified</span>{" "}
            {unverifiedCount} host(s) discovered but not confirmed via HTTP probing.
          </p>
        </article>
      ) : null}

      <article className="flat-panel fade-in">
        <h2>Enumeration Summary</h2>
        <p>
          <strong>Passive count:</strong> {data.passive_count ?? 0}
        </p>
        <p>
          <strong>Brute-force count:</strong> {data.brute_force_count ?? 0}
        </p>
        <p>
          <strong>Wordlist entries:</strong> {data.wordlist?.combined_entries ?? 0}
        </p>
        <p>
          <strong>Security analysis coverage:</strong>{" "}
          {data.analyzed_live_subdomains ?? 0} live hosts
        </p>
        <p>
          <strong>Scan mode:</strong>{" "}
          {data.scan_mode === "full" ? "Full Scan" : "Quick Scan"}
        </p>
      </article>

      <article className="flat-panel fade-in">
        <h2>Charts</h2>
        <Charts
          liveCount={liveCount}
          deadCount={inactiveCount + unverifiedCount}
          statusCodes={data.status_codes}
        />
      </article>

      <article className="flat-panel fade-in">
        <h2>Results Table</h2>
        <ResultsTable data={data} />
      </article>
    </section>
  );
}

export default Dashboard;
