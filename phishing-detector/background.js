chrome.runtime.onInstalled.addListener(() => {
    chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [1], 
        addRules: [{
            "id": 1,
            "priority": 1,
            "action": { 
                "type": "redirect", 
                "redirect": { "regexSubstitution": chrome.runtime.getURL("checking.html") + "?url=\\0" } 
            },
            "condition": { 
                "regexFilter": "^https?://.*", 
                "resourceTypes": ["main_frame"] 
            }
        }]
    });
    console.log("🚀 Hệ thống đã sẵn sàng với Static Ruleset 100.000 domain.");
});