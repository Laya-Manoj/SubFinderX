import { useEffect, useRef } from "react";

function Charts({ liveCount, inactiveCount, riskSummary }) {
  const pieRef = useRef(null);
  const barRef = useRef(null);
  const pieChartRef = useRef(null);
  const barChartRef = useRef(null);

  const risk = riskSummary || { high: 0, medium: 0, low: 0 };

  useEffect(() => {
    if (!window.Chart || !pieRef.current || !barRef.current) {
      return;
    }

    if (pieChartRef.current) {
      pieChartRef.current.destroy();
    }
    if (barChartRef.current) {
      barChartRef.current.destroy();
    }

    pieChartRef.current = new window.Chart(pieRef.current, {
      type: "pie",
      data: {
        labels: ["Live", "Inactive"],
        datasets: [
          {
            data: [liveCount, inactiveCount],
            backgroundColor: ["#22c55e", "#64748b"],
            borderWidth: 0,
          },
        ],
      },
      options: {
        animation: { duration: 700, easing: "easeOutQuart" },
        plugins: {
          legend: { position: "bottom", labels: { color: "#cbd5e1" } },
          tooltip: { enabled: true },
        },
      },
    });

    barChartRef.current = new window.Chart(barRef.current, {
      type: "bar",
      data: {
        labels: ["High", "Medium", "Low"],
        datasets: [
          {
            label: "Live Hosts by Risk",
            data: [risk.high ?? 0, risk.medium ?? 0, risk.low ?? 0],
            backgroundColor: ["#ef4444", "#f59e0b", "#22c55e"],
            borderRadius: 6,
          },
        ],
      },
      options: {
        animation: { duration: 700, easing: "easeOutQuart" },
        plugins: {
          legend: { display: false },
          tooltip: { enabled: true },
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: { stepSize: 1, color: "#94a3b8" },
            grid: { color: "#334155" },
          },
          x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } },
        },
      },
    });
  }, [liveCount, inactiveCount, risk.high, risk.medium, risk.low]);

  return (
    <div className="charts">
      <div className="chart-card">
        <h3>Live vs Inactive Hosts</h3>
        <canvas ref={pieRef} />
      </div>
      <div className="chart-card">
        <h3>Risk Level Distribution</h3>
        <canvas ref={barRef} />
      </div>
    </div>
  );
}

export default Charts;
