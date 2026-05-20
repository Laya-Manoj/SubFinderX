import { useState } from "react";

const API_BASE = "http://127.0.0.1:5000";

function ScreenshotGallery({ subdomains }) {
  const [preview, setPreview] = useState(null);
  const liveWithShots = (subdomains || []).filter(
    (item) => item.status_label === "active" || item.is_live
  );

  if (!liveWithShots.length) {
    return null;
  }

  return (
    <div className="screenshot-gallery">
      <div className="screenshot-grid">
        {liveWithShots.map((item) => {
          const src = item.screenshot_url ? `${API_BASE}${item.screenshot_url}` : null;
          return (
            <article key={item.name} className="screenshot-card">
              <h4>{item.name}</h4>
              {src ? (
                <button
                  type="button"
                  className="screenshot-thumb-btn"
                  onClick={() => setPreview({ src, name: item.name })}
                >
                  <img src={src} alt={`Screenshot of ${item.name}`} className="screenshot-thumb" />
                </button>
              ) : (
                <div className="screenshot-fallback">No Preview Available</div>
              )}
            </article>
          );
        })}
      </div>

      {preview ? (
        <div className="screenshot-modal" role="dialog" aria-modal="true">
          <div className="screenshot-modal-content">
            <button type="button" className="modal-close" onClick={() => setPreview(null)}>
              Close
            </button>
            <h4>{preview.name}</h4>
            <img src={preview.src} alt={`Expanded screenshot of ${preview.name}`} />
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default ScreenshotGallery;
