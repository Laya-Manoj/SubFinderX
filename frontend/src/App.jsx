import { useEffect, useRef, useState } from "react";
import ScanForm from "./components/ScanForm";
import Dashboard from "./components/Dashboard";

function App() {
  useEffect(() => {
    document.title = "SubFinderX: Attack Surface Analyzer";
  }, []);

  const [loading, setLoading] = useState(false);
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
    setResults(null);

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
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Scan failed");
      }
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
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
      <ScanForm onSubmit={startScan} loading={loading} />
      {error ? <p className="error">{error}</p> : null}
      {results ? (
        <section ref={resultsRef}>
          <Dashboard data={results} />
        </section>
      ) : null}
    </main>
  );
}

export default App;
