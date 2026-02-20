document.getElementById('scanBtn').addEventListener('click', async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // Open Localhost with URL param
    // Encode the URL to ensure special characters don't break the query 
    const scanUrl = `http://127.0.0.1:5000/scan?url=${encodeURIComponent(tab.url)}`;

    chrome.tabs.create({ url: scanUrl });
});
