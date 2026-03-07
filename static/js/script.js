async function fetchLogs() {
    const res = await fetch('/logs_analysis');
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

// Store the state of clicked buttons
let clickedButtons = {};

function handleLabelClick(event, element) {
    event.preventDefault(); // Prevent immediate navigation
    
    const caseId = element.dataset.caseId;
    const label = element.dataset.label;
    const url = element.href;
    
    // Get both buttons in this case
    const buttonGroup = document.getElementById(`label-buttons-${caseId}`);
    const buttons = buttonGroup.querySelectorAll('.label-btn');
    
    // Reset both buttons to their original outline styles first
    buttons.forEach(btn => {
        btn.classList.remove('btn-secondary');
        if (btn.dataset.label === 'malicious') {
            btn.classList.add('btn-outline-danger');
        } else {
            btn.classList.add('btn-outline-success');
        }
    });
    
    // Then make ONLY the clicked button grey
    element.classList.remove('btn-outline-danger', 'btn-outline-success');
    element.classList.add('btn-secondary');
    
    // Store that this specific button has been clicked
    if (!clickedButtons[caseId]) {
        clickedButtons[caseId] = {};
    }
    clickedButtons[caseId][label] = true;
    
    // Optional: Actually perform the label action
    fetch(url, {
        method: 'GET',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => {
        if (!response.ok) {
            // If the request fails, revert just this button
            revertButtonColor(caseId, element);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        revertButtonColor(caseId, element);
    });
}

function revertButtonColor(caseId, element) {
    // Remove grey class
    element.classList.remove('btn-secondary');
    
    // Add back the appropriate outline class
    if (element.dataset.label === 'malicious') {
        element.classList.add('btn-outline-danger');
    } else {
        element.classList.add('btn-outline-success');
    }
    
    // Update stored state
    if (clickedButtons[caseId]) {
        delete clickedButtons[caseId][element.dataset.label];
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const savedClicks = localStorage.getItem('clickedLabelButtons');
    if (savedClicks) {
        clickedButtons = JSON.parse(savedClicks);
        
        Object.keys(clickedButtons).forEach(caseId => {
            Object.keys(clickedButtons[caseId]).forEach(label => {
                const buttonGroup = document.getElementById(`label-buttons-${caseId}`);
                if (buttonGroup) {
                    const buttons = buttonGroup.querySelectorAll('.label-btn');
                    buttons.forEach(btn => {
                        // Reset all buttons first
                        btn.classList.remove('btn-secondary');
                        if (btn.dataset.label === 'malicious') {
                            btn.classList.add('btn-outline-danger');
                        } else {
                            btn.classList.add('btn-outline-success');
                        }
                        
                        // Grey out only the saved button
                        if (btn.dataset.label === label) {
                            btn.classList.remove('btn-outline-danger', 'btn-outline-success');
                            btn.classList.add('btn-secondary');
                        }
                    });
                }
            });
        });
    }
  
    
    // Save state when page unloads if using localStorage
    window.addEventListener('beforeunload', function() {
        localStorage.setItem('clickedLabelButtons', JSON.stringify(clickedButtons));
    });
});