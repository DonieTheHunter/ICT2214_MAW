async function fetchLogs() {
const res = await fetch('/logs');
const data = await res.json();
document.getElementById('log-area').textContent = data.join('');
}
setInterval(fetchLogs, 2000);
fetchLogs();

let shownCases = new Set();
async function pollAlert() {
    const res = await fetch("/alert");
    const data = await res.json();
    if (data.alerts && data.alerts.length > 0) {
        data.alerts.forEach(alertItem => {
            if (!shownCases.has(alertItem.case_id)) {
                shownCases.add(alertItem.case_id);
                alert(alertItem.alert);
            }
        });
    }
}
setInterval(pollAlert, 1000);
pollAlert();