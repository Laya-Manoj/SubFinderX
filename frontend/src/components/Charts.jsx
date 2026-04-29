import { useEffect, useRef } from "react";

function Charts({ liveCount, deadCount, statusCodes }) {
  const pieRef = useRef(null);
  const barRef = useRef(null);
  const pieChartRef = useRef(null);
  const barChartRef = useRef(null);

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
        labels: ["Live", "Dead"],
        datasets: [{ data: [liveCount, deadCount], backgroundColor: ["#22c55e", "#ef4444"], borderWidth: 0 }],
      },
      options: {
        animation: { duration: 900, easing: "easeOutQuart" },
        plugins: {
          legend: { position: "bottom", labels: { color: "#cbd5e1" } },
          tooltip: { enabled: true },
        },
      },
    });

    barChartRef.current = new window.Chart(barRef.current, {
      type: "bar",
      data: {
        labels: Object.keys(statusCodes),
        datasets: [{ label: "Status Codes", data: Object.values(statusCodes), backgroundColor: "#3b82f6", borderRadius: 6 }],
      },
      options: {
        animation: { duration: 900, easing: "easeOutQuart" },
        plugins: {
          legend: { display: true, labels: { color: "#cbd5e1" } },
          tooltip: { enabled: true },
        },
        scales: {
          y: { beginAtZero: true, ticks: { color: "#94a3b8" }, grid: { color: "#334155" } },
          x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } },
        },
      },
    });
  }, [liveCount, deadCount, statusCodes]);

  return (
    <div className="charts">
      <div className="chart-card">
        <h3>Live vs Dead</h3>
        <canvas ref={pieRef} />
      </div>
      <div className="chart-card">
        <h3>Status Code Distribution</h3>
        <canvas ref={barRef} />
      </div>
    </div>
  );
}

export default Charts;
