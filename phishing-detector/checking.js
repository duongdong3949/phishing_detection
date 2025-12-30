const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url');

async function verify() {
    if (!targetUrl) return;

    try {
        const urlObj = new URL(targetUrl);
        const domain = urlObj.hostname;

        const res = await fetch('http://localhost:8011/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: targetUrl })
        });
        const data = await res.json();

        if (data.prediction === "1") {
            window.location.href = "warning.html";
        } else {
            await chrome.declarativeNetRequest.updateDynamicRules({
                addRules: [{
                    "id": Math.floor(Math.random() * 1000000) + 2,
                    "priority": 2, 
                    "action": { "type": "allow" },
                    "condition": { 
                        "urlFilter": `||${domain}^`, 
                        "resourceTypes": ["main_frame"] 
                    }
                }]
            });

            window.location.href = targetUrl;
        }
    } catch (e) {
        console.error("Lỗi xác thực:", e);
        window.location.href = targetUrl; 
    }
}

verify();