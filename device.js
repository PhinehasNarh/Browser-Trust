document.addEventListener('DOMContentLoaded', function() {
    // Collect device info
    const deviceInfo = {
        user_agent: navigator.userAgent,
        screen_width: screen.width,
        screen_height: screen.height,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        languages: navigator.languages,
        cookie_enabled: navigator.cookieEnabled
    };

    // Send to Flask backend
    fetch('/submit-device-info', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(deviceInfo)
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('result').innerHTML = `
            <h2>Trust Assessment Result</h2>
            <p>Score: ${data.trust_score}</p>
            <p>Verdict: ${data.verdict}</p>
        `;
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('result').innerHTML = 
            '<p>Error assessing device trust</p>';
    });
});
