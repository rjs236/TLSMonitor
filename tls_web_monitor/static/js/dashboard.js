/**
 * Dashboard & Security Console JavaScript
 * Provides live telemetry charts, attack simulation triggers, and cryptographic audit controls.
 */

document.addEventListener("DOMContentLoaded", function () {
    // Initialize charts if on dashboard page
    initSeverityChart();

    // Auto-refresh stats every 30 seconds if on dashboard
    if (document.getElementById("stats-dashboard-container")) {
        setInterval(fetchLatestStats, 30000);
    }
});

/**
 * Initializes Alert Severity Distribution Chart using Chart.js (or fallback)
 */
function initSeverityChart() {
    const canvas = document.getElementById("severityChart");
    if (!canvas) return;

    const high = parseInt(canvas.dataset.high || "0", 10);
    const med = parseInt(canvas.dataset.med || "0", 10);
    const low = parseInt(canvas.dataset.low || "0", 10);

    if (window.Chart) {
        new Chart(canvas.getContext("2d"), {
            type: "doughnut",
            data: {
                labels: ["High Severity", "Medium Severity", "Low Severity"],
                datasets: [{
                    data: [high, med, low],
                    backgroundColor: ["#ef4444", "#f59e0b", "#3b82f6"],
                    borderColor: "#132042",
                    borderWidth: 2,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: "#94a3b8",
                            font: { family: "Inter", size: 12 }
                        }
                    }
                },
                cutout: "70%"
            }
        });
    }
}

/**
 * Fetches updated dashboard statistics via JSON API
 */
async function fetchLatestStats() {
    try {
        const resp = await fetch("/api/dashboard/stats");
        if (resp.ok) {
            const data = await resp.json();
            const elTotal = document.getElementById("stat-total-requests");
            const elSuccess = document.getElementById("stat-success-logins");
            const elFailed = document.getElementById("stat-failed-logins");
            const elAlerts = document.getElementById("stat-open-alerts");

            if (elTotal) elTotal.textContent = data.total_requests;
            if (elSuccess) elSuccess.textContent = data.success_logins;
            if (elFailed) elFailed.textContent = data.failed_logins;
            if (elAlerts) elAlerts.textContent = data.open_alerts;
        }
    } catch (err) {
        console.warn("Telemetry refresh failed:", err);
    }
}

/**
 * Triggers a controlled attack probe from the Security Testing console
 */
async function triggerTestAttack(attackType, btnElement) {
    const outputBox = document.getElementById("testConsoleOutput");
    if (!outputBox) return;

    if (btnElement) {
        btnElement.disabled = true;
        btnElement.dataset.origText = btnElement.textContent;
        btnElement.textContent = "Executing...";
    }

    outputBox.innerHTML = `<span style="color: #00f5d4;">[*] Transmitting controlled '${attackType}' payload to server inspection engine...</span>\n`;

    try {
        const resp = await fetch("/api/test-attack", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ attack_type: attackType })
        });

        const data = await resp.json();

        if (resp.ok) {
            outputBox.innerHTML += `\n<span style="color: #10b981;">[✓] RESPONSE STATUS: ${resp.status} OK</span>\n`;
            outputBox.innerHTML += `<span style="color: #f8fafc;">[✓] Status:           <b>${data.status}</b></span>\n`;
            if (data.alert_type) {
                outputBox.innerHTML += `<span style="color: #ef4444;">[!] Alert Generated:  <b>${data.alert_type}</b> (Severity: ${data.severity})</span>\n`;
                outputBox.innerHTML += `<span style="color: #f8fafc;">[!] Alert Record ID:   #${data.alert_id}</span>\n`;
            }
            if (data.record_id) {
                outputBox.innerHTML += `<span style="color: #ef4444;">[!] Record Tampered:   Log #${data.record_id}</span>\n`;
                outputBox.innerHTML += `<span style="color: #94a3b8;">    Original Path:     ${data.original_path}</span>\n`;
                outputBox.innerHTML += `<span style="color: #f59e0b;">    Injected Path:     ${data.tampered_path}</span>\n`;
            }
            outputBox.innerHTML += `<span style="color: #00b4d8;">[i] Server Message:    ${data.message}</span>\n`;
            outputBox.innerHTML += `\n<span style="color: #10b981;">[✓] Test complete. Check the Threat Alerts or Logs tab to inspect the persistent record.</span>`;
        } else {
            outputBox.innerHTML += `\n<span style="color: #ef4444;">[!] ERROR (${resp.status}): ${data.message || "Request failed"}</span>`;
        }
    } catch (err) {
        outputBox.innerHTML += `\n<span style="color: #ef4444;">[!] Network error executing probe: ${err}</span>`;
    } finally {
        if (btnElement) {
            btnElement.disabled = false;
            btnElement.textContent = btnElement.dataset.origText || "Run Test";
        }
    }
}

/**
 * Triggers cryptographic HMAC log integrity audit
 */
async function triggerIntegrityAudit(btnElement) {
    const outputBox = document.getElementById("testConsoleOutput");
    if (!outputBox) return;

    if (btnElement) {
        btnElement.disabled = true;
        btnElement.dataset.origText = btnElement.textContent;
        btnElement.textContent = "Verifying HMACs...";
    }

    outputBox.innerHTML = `<span style="color: #00f5d4;">[*] Starting Cryptographic HMAC-SHA256 Log Integrity Audit...</span>\n`;
    outputBox.innerHTML += `<span style="color: #94a3b8;">[*] Scanning SQLite 'request_logs' table and recomputing HMACs...</span>\n`;

    try {
        const resp = await fetch("/api/audit/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        const data = await resp.json();

        if (resp.ok) {
            outputBox.innerHTML += `\n<span style="color: #10b981;">[✓] AUDIT RESULT: ${data.status}</span>\n`;
            outputBox.innerHTML += `<span style="color: #f8fafc;">[✓] Records Audited:        ${data.records_audited}</span>\n`;
            outputBox.innerHTML += `<span style="color: ${data.tampered_records_found > 0 ? '#ef4444' : '#10b981'}; font-weight: bold;">[!] Tampered Records Found: ${data.tampered_records_found}</span>\n`;
            outputBox.innerHTML += `<span style="color: #00b4d8;">[i] Audit Details:          ${data.details}</span>\n`;

            if (data.tampered_records && data.tampered_records.length > 0) {
                outputBox.innerHTML += `\n<span style="color: #ef4444; font-weight: bold;">[!] DETECTED TAMPERED LOG ENTRIES:</span>\n`;
                data.tampered_records.forEach(r => {
                    outputBox.innerHTML += `<span style="color: #f59e0b;">  - Log ID #${r.id} (${r.path}):\n    Stored Sig:   ${r.stored_signature}\n    Expected Sig: ${r.expected_signature}</span>\n`;
                });
            }
        } else {
            outputBox.innerHTML += `\n<span style="color: #ef4444;">[!] Audit failed: ${data.message}</span>`;
        }
    } catch (err) {
        outputBox.innerHTML += `\n<span style="color: #ef4444;">[!] Error: ${err}</span>`;
    } finally {
        if (btnElement) {
            btnElement.disabled = false;
            btnElement.textContent = btnElement.dataset.origText || "Verify Log Integrity";
        }
    }
}

