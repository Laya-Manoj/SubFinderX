import { useEffect, useRef, useState } from "react";
import ScanForm from "./components/ScanForm";
import Dashboard from "./components/Dashboard";

const LOADING_PHASES = [
  { at: 4000, message: "Validating hosts..." },
  { at: 9000, message: "Analyzing security headers..." },
  { at: 14000, message: "Generating report..." },
];

const QUICK_SCAN_SLOW_WARNING_MS = 25000;

function App() {
  useEffect(() => {
    document.title = "SubFinderX: Attack Surface Analyzer";
  }, []);

  const [loading, setLoading] = useState(false);
  const [loadingPhase, setLoadingPhase] = useState("Collecting subdomains...");
  const [slowScanWarning, setSlowScanWarning] = useState("");
  const [error, setError] = useState("");
  const [results, setResults] = useState(null);
  const resultsRef = useRef(null);

  useEffect(() => {
    if (results && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [results]);

  const startScan = async ({ domain, wordlistText, wordlistFile, scanMode }) => {
    setLoading(true);
    setError("");
    setSlowScanWarning("");
    setResults(null);
    setLoadingPhase("Collecting subdomains...");

    const phaseTimers = LOADING_PHASES.map(({ at, message }) =>
      setTimeout(() => setLoadingPhase(message), at)
    );
    const slowWarningTimer = setTimeout(() => {
      if (scanMode === "quick") {
        setSlowScanWarning(
          "Quick scan taking longer than expected. Partial results may be returned."
        );
      }
    }, QUICK_SCAN_SLOW_WARNING_MS);

    try {
      const formData = new FormData();
      formData.append("domain", domain);
      formData.append("authorized", "true");
      formData.append("scan_mode", scanMode);
      formData.append("wordlist_text", wordlistText || "");
      if (wordlistFile) {
        formData.append("wordlist_file", wordlistFile);
      }

      const response = await fetch("http://127.0.0.1:5000/scan", {
        method: "POST",
        body: formData,
        mode: "cors",
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Scan failed");
      }
      if (data.warning) {
        setSlowScanWarning(data.warning);
      }
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      phaseTimers.forEach(clearTimeout);
      clearTimeout(slowWarningTimer);
      setLoading(false);
    }
  };

  return (
    <main className="container">
      <nav className="top-navbar">
        <div className="brand-wrap">
          <span className="brand-icon" aria-hidden="true">🛡️</span>
          <span className="brand-logo">SubFinderX</span>
        </div>
        <span className="brand-title">Attack Surface Analyzer</span>
      </nav>
      <section className="hero-section fade-in">
        <h1>Attack Surface Analyzer</h1>
        <p>Enumerate, analyze, and visualize subdomains in real-time</p>
      </section>
      <ScanForm onSubmit={startScan} loading={loading} loadingPhase={loadingPhase} />
      {slowScanWarning ? <p className="slow-warning">{slowScanWarning}</p> : null}
      {error ? <p className="error">{error}</p> : null}
      {loading ? (
        <section className="loading-panel fade-in" aria-live="polite">
          <span className="spinner" aria-hidden="true" />
          <p className="loading-text">{loadingPhase}</p>
        </section>
      ) : null}
      {results ? (
        <section ref={resultsRef}>
          <Dashboard data={results} />
        </section>
      ) : null}
    </main>
  );
}

export default App;
