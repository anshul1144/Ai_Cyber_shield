// AI Cyber Shield Dashboard - JavaScript Handler
let socket;
let trafficChart;
const maxChartPoints = 15;
let chartLabels = [];
let chartRxData = [];
let chartTxData = [];

// Initialize Telemetry Chart
function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartLabels,
            datasets: [
                {
                    label: 'Rx Traffic (KB/s)',
                    data: chartRxData,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2
                },
                {
                    label: 'Tx Traffic (KB/s)',
                    data: chartTxData,
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#9ca3af' }
                },
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#9ca3af' }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#f3f4f6' }
                }
            }
        }
    });
}

function updateChart(rxRate, txRate) {
    const timeStr = new Date().toLocaleTimeString();
    
    chartLabels.push(timeStr);
    chartRxData.push((rxRate / 1024).toFixed(1)); // Convert to KB/s
    chartTxData.push((txRate / 1024).toFixed(1)); // Convert to KB/s
    
    if (chartLabels.length > maxChartPoints) {
        chartLabels.shift();
        chartRxData.shift();
        chartTxData.shift();
    }
    
    trafficChart.update();
}

// Connect WebSocket
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    socket = new WebSocket(wsUrl);
    
    socket.onopen = () => {
        console.log("WebSocket connected successfully.");
        document.getElementById("system-status").innerHTML = '<div class="status-dot"></div> MONITORING ACTIVATED';
        document.getElementById("system-status").style.color = "var(--success)";
        document.getElementById("system-status").style.borderColor = "rgba(16, 185, 129, 0.3)";
    };
    
    socket.onclose = () => {
        console.warn("WebSocket disconnected. Retrying in 3 seconds...");
        document.getElementById("system-status").innerHTML = '<div class="status-dot" style="background-color: var(--danger); box-shadow: 0 0 10px var(--danger);"></div> CONNECTION LOST';
        document.getElementById("system-status").style.color = "var(--danger)";
        document.getElementById("system-status").style.borderColor = "rgba(239, 68, 68, 0.3)";
        setTimeout(connectWebSocket, 3000);
    };
    
    socket.onmessage = (event) => {
        const payload = JSON.parse(event.data);
        handleTelemetry(payload);
    };
}

// Handle incoming telemetry stream
function handleTelemetry(data) {
    // 1. Update Core Metric Widgets
    document.getElementById("val-connections").innerText = data.network.connection_count;
    
    const totalTraffic = (data.network.bytes_sent_rate + data.network.bytes_recv_rate) / 1024;
    document.getElementById("val-traffic").innerText = `${totalTraffic.toFixed(1)} KB/s`;
    
    document.getElementById("val-file-rate").innerText = `${data.file.modification_rate} / min`;
    
    // File rate status colors
    const fileTrend = document.getElementById("val-file-status");
    if (data.file.modification_rate > 100) {
        fileTrend.innerText = "⚠ Extreme Activity";
        fileTrend.style.color = "var(--danger)";
    } else if (data.file.modification_rate > 20) {
        fileTrend.innerText = "⚠ High Activity";
        fileTrend.style.color = "var(--warning)";
    } else {
        fileTrend.innerText = "✔ Idle State";
        fileTrend.style.color = "var(--success)";
    }
    
    // Anomaly values
    const anomalyPercent = data.anomaly.anomaly_score;
    document.getElementById("val-anomaly").innerText = `${anomalyPercent.toFixed(1)}%`;
    const anomalyTrend = document.getElementById("val-anomaly-status");
    if (data.anomaly.is_anomaly) {
        anomalyTrend.innerText = "⚠ Anomaly flag set";
        anomalyTrend.style.color = "var(--danger)";
    } else {
        anomalyTrend.innerText = "✔ Safe baseline";
        anomalyTrend.style.color = "var(--success)";
    }
    
    // Update live graph
    updateChart(data.network.bytes_recv_rate, data.network.bytes_sent_rate);
    
    // 2. Alert Banner handler
    const alertBanner = document.getElementById("threat-alert");
    if (data.threat.is_threat) {
        document.getElementById("alert-type").innerText = `CRITICAL THREAT DETECTED: ${data.threat.attack_type}`;
        document.getElementById("alert-details").innerText = `Machine Learning Model matched threat type. Confidence: ${(data.threat.confidence * 100).toFixed(0)}%. Severity: ${data.threat.severity_score}/100.`;
        alertBanner.style.display = "flex";
    } else {
        // Only hide if not simulated sticky alert
        if (!data.threat.simulated_attack) {
            alertBanner.style.display = "none";
        }
    }
    
    // 3. Process Table list
    const procTbody = document.getElementById("process-list");
    procTbody.innerHTML = "";
    data.process.top_processes.forEach(proc => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${proc.pid}</td>
            <td style="font-weight: 600;">${proc.name}</td>
            <td style="color: ${proc.cpu_percent > 50 ? 'var(--danger)' : 'var(--text-primary)'};">${proc.cpu_percent}%</td>
            <td style="color: ${proc.memory_percent > 30 ? 'var(--warning)' : 'var(--text-primary)'};">${proc.memory_percent}%</td>
        `;
        procTbody.appendChild(row);
    });
    
    // 4. Update Audit logs
    const logList = document.getElementById("audit-logs");
    logList.innerHTML = "";
    
    // Render suspicious file events, high logins, threat logs
    const mergedAuditLogs = [];
    
    // Add threat predictions
    if (data.threat.is_threat) {
        mergedAuditLogs.push({
            type: "threat",
            timestamp: new Date().toLocaleTimeString(),
            message: `[AI Threat Classifier] CLASSIFIED THREAT: ${data.threat.attack_type} (Confidence: ${(data.threat.confidence * 100).toFixed(0)}%)`
        });
    }
    if (data.anomaly.is_anomaly) {
        mergedAuditLogs.push({
            type: "threat",
            timestamp: new Date().toLocaleTimeString(),
            message: `[AI Anomaly Detector] CPU/RAM/process allocation anomaly identified (Score: ${data.anomaly.anomaly_score}%)`
        });
    }
    
    // Add file monitor notifications
    data.file.event_history.slice(0, 8).forEach(evt => {
        mergedAuditLogs.push({
            type: "file",
            timestamp: evt.timestamp,
            message: `[File System] ${evt.type}: ${evt.filename}`
        });
    });
    
    // Add scanned log entries
    data.log.suspicious_entries.slice(0, 10).forEach(ent => {
        mergedAuditLogs.push({
            type: "log",
            timestamp: ent.timestamp,
            message: `[Audit Log] ${ent.message}`
        });
    });
    
    // Sort combined events
    mergedAuditLogs.forEach(log => {
        const div = document.createElement("div");
        div.className = `log-item ${log.type === 'threat' ? 'threat' : ''}`;
        div.innerHTML = `
            <span class="log-timestamp">${log.timestamp}</span>
            <span class="log-msg">${log.message}</span>
        `;
        logList.appendChild(div);
    });
    
    if (mergedAuditLogs.length === 0) {
        logList.innerHTML = '<div class="log-item"><span class="log-timestamp">INFO</span><span class="log-msg">Scanning channels active... No anomalies identified.</span></div>';
    }
}

// Dismiss simulated threat display manually
function dismissAlert() {
    document.getElementById("threat-alert").style.display = "none";
    setSim('None');
}

// Call threat simulator endpoint
function setSim(attackType) {
    // Highlight correct simulation selector button
    const buttons = document.querySelectorAll(".simulator-grid button");
    buttons.forEach(btn => btn.classList.remove("btn-active"));
    
    const activeBtnId = `sim-${attackType.replace(/\s+/g, '-')}`;
    const activeBtn = document.getElementById(activeBtnId);
    if (activeBtn) activeBtn.classList.add("btn-active");
    
    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({
            action: "trigger_simulation",
            attack_type: attackType
        }));
    }
}

window.onload = () => {
    initChart();
    connectWebSocket();
};
