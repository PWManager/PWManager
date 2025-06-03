// Background service worker for PWManager extension

// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
    console.log('PWManager extension installed');
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('Received message:', request);
    
    if (request.type === 'getPasswords') {
        console.log('Fetching passwords for URL:', request.url);
        
        // Make request to local server
        fetch(`http://localhost:8080/suggest/${encodeURIComponent(request.url)}`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            }
        })
        .then(response => {
            console.log('Server response status:', response.status);
            return response.json();
        })
        .then(data => {
            console.log('Received data from server:', data);
            
            // Convert object to array format
            const passwords = Object.entries(data).map(([site_name, password]) => ({
                site_name,
                password
            }));
            
            console.log('Sending response to content script:', { success: true, passwords });
            sendResponse({ success: true, passwords });
        })
        .catch(error => {
            console.error('Error fetching passwords:', error);
            sendResponse({ success: false, error: error.message });
        });
        
        return true; // Will respond asynchronously
    }
}); 