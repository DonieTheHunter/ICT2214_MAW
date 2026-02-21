async function fetchLogs() {
const res = await fetch('/logs');
const data = await res.json();
document.getElementById('log-area').textContent = data.join('');
}
setInterval(fetchLogs, 2000);
fetchLogs();

let lastAlertId = 0;
async function pollAlert() {
const res = await fetch("/alert");
const data = await res.json();
if (data.alert_id > lastAlertId && data.alert) {
    lastAlertId = data.alert_id;
    alert(data.alert);
}
}
setInterval(pollAlert, 1000);
pollAlert();