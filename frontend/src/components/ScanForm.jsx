import { useState } from "react";

function ScanForm({ onSubmit, loading }) {
  const [domain, setDomain] = useState("");
  const [wordlistText, setWordlistText] = useState("");
  const [wordlistFile, setWordlistFile] = useState(null);
  const [scanMode, setScanMode] = useState("quick");

  const handleSubmit = (event) => {
    event.preventDefault();
    onSubmit({ domain, wordlistText, wordlistFile, scanMode });
  };

  return (
    <form className="input-panel fade-in" onSubmit={handleSubmit}>
      <h2>Target Input</h2>
      <label className="field-label">
        Target Domain
        <input
          type="text"
          placeholder="example.com"
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
          required
        />
      </label>

      <label className="field-label">
        Scan Mode
        <select value={scanMode} onChange={(event) => setScanMode(event.target.value)}>
          <option value="quick">Quick Scan</option>
          <option value="full">Full Scan</option>
        </select>
      </label>

      <label className="field-label">
        Custom Wordlist (Optional)
        <input
          type="file"
          accept=".txt,text/plain"
          onChange={(event) => setWordlistFile(event.target.files?.[0] || null)}
        />
      </label>

      <label className="field-label">
        Paste Wordlist (Optional)
        <textarea
          rows={6}
          placeholder={"admin\napi\nstaging"}
          value={wordlistText}
          onChange={(event) => setWordlistText(event.target.value)}
        />
      </label>

      <div className="warning-box">
        This tool is for authorized security testing only.
      </div>

      <button type="submit" disabled={loading} className="scan-btn">
        {loading ? (
          <>
            <span className="spinner" aria-hidden="true" />
            Scanning...
          </>
        ) : (
          "Start Recon"
        )}
      </button>
      {loading ? <p className="loading-text">Scanning target... please wait</p> : null}
    </form>
  );
}

export default ScanForm;
