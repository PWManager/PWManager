// Cache for connection status
let connectionStatus = {
    isConnected: false,
    lastCheck: 0,
    checkInterval: 10000
};

// Create and inject the popup element
const popup = document.createElement('div');
popup.id = 'pwmanager-suggestions';
popup.innerHTML = `
    <div class="header">
        <span>Saved Passwords</span>
        <button class="close-button">×</button>
    </div>
    <div class="content"></div>
    <div class="footer">PWManager</div>
`;
document.body.appendChild(popup);

// Add styles
const link = document.createElement('link');
link.rel = 'stylesheet';
link.href = chrome.runtime.getURL('styles.css');
document.head.appendChild(link);

// Variables
let activeInput = null;
let hideTimeout = null;

// Create password item
function createPasswordItem(siteName, password) {
    const item = document.createElement('div');
    item.className = 'password-item';
    item.innerHTML = `
        <div class="site-name">${siteName}</div>
        <div class="password-text">${password}</div>
    `;
    
    item.addEventListener('click', () => {
        if (activeInput) {
            try {
                // Focus the input
                activeInput.focus();
                
                // Set the value
                activeInput.value = password;
                
                // Dispatch events
                ['input', 'change'].forEach(eventType => {
                    activeInput.dispatchEvent(new Event(eventType, {
                        bubbles: true,
                        cancelable: true
                    }));
                });
                
                // Hide popup
                popup.style.display = 'none';
            } catch (error) {
                console.error('Error filling password:', error);
            }
        }
    });
    
    return item;
}

// Show password suggestions
async function showPasswordSuggestions(input) {
    console.log('Showing password suggestions for input:', input);
    activeInput = input;
    
    try {
        // Request passwords from background script
        const response = await chrome.runtime.sendMessage({
            type: 'getPasswords',
            url: window.location.href
        });
        
        console.log('Received response:', response);
        
        if (response.success && response.passwords && response.passwords.length > 0) {
            const content = popup.querySelector('.content');
            content.innerHTML = '';
            
            response.passwords.forEach(({ site_name, password }) => {
                content.appendChild(createPasswordItem(site_name, password));
            });
            
            // Position popup near input
            const rect = input.getBoundingClientRect();
            const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
            const scrollLeft = window.pageXOffset || document.documentElement.scrollLeft;
            
            let left = rect.left + scrollLeft;
            let top = rect.bottom + scrollTop + 5;
            
            // Ensure popup stays within viewport
            if (left + popup.offsetWidth > window.innerWidth + scrollLeft) {
                left = window.innerWidth + scrollLeft - popup.offsetWidth - 10;
            }
            
            if (top + popup.offsetHeight > window.innerHeight + scrollTop) {
                top = rect.top + scrollTop - popup.offsetHeight - 5;
            }
            
            popup.style.left = `${left}px`;
            popup.style.top = `${top}px`;
            popup.style.display = 'block';
            
            console.log('Popup displayed at:', { left, top });
        } else {
            console.log('No passwords found or invalid response');
        }
    } catch (error) {
        console.error('Error getting passwords:', error);
    }
}

// Add event listeners
document.addEventListener('mouseover', (e) => {
    if (e.target.tagName === 'INPUT' && e.target.type === 'password') {
        console.log('Password input detected:', e.target);
        showPasswordSuggestions(e.target);
    }
});

// Close button handler
popup.querySelector('.close-button').addEventListener('click', () => {
    console.log('Close button clicked');
    popup.style.display = 'none';
});

// Click outside handler
document.addEventListener('click', (e) => {
    if (!popup.contains(e.target) && e.target.tagName !== 'INPUT') {
        console.log('Click outside popup');
        popup.style.display = 'none';
    }
});

// Check connection status with timeout
function checkConnection() {
    const now = Date.now();
    if (now - connectionStatus.lastCheck < connectionStatus.checkInterval) {
        return Promise.resolve(connectionStatus.isConnected);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    return fetch('http://localhost:8080/passwords', {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' },
        mode: 'cors'
    })
    .then(response => {
        clearTimeout(timeoutId);
        connectionStatus.isConnected = response.ok;
        connectionStatus.lastCheck = now;
        return response.ok;
    })
    .catch(() => {
        clearTimeout(timeoutId);
        connectionStatus.isConnected = false;
        connectionStatus.lastCheck = now;
        return false;
    });
}

// Add hover event listeners to password inputs
function addPasswordInputListeners() {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    
    passwordInputs.forEach(input => {
        if (!input.hasAttribute('data-pwmanager-listener')) {
            input.setAttribute('data-pwmanager-listener', 'true');
            
            input.addEventListener('mouseenter', () => {
                checkConnection().then(isConnected => {
                    if (!isConnected) {
                        popup.style.display = 'none';
                        return;
                    }

                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 2000);

                    fetch(`http://localhost:8080/suggest/${encodeURIComponent(window.location.href)}`, {
                        signal: controller.signal,
                        headers: { 'Accept': 'application/json' },
                        mode: 'cors'
                    })
                    .then(response => {
                        clearTimeout(timeoutId);
                        return response.json();
                    })
                    .then(passwords => {
                        showPasswordSuggestions(input);
                    })
                    .catch(() => {
                        clearTimeout(timeoutId);
                        popup.style.display = 'none';
                    });
                });
            });
        }
    });
}

// Remove all mouseleave and click handlers since we want the popup to stay visible
popup.removeEventListener('mouseleave', () => {});
document.removeEventListener('click', () => {});

// Setup observers and listeners
addPasswordInputListeners();

const passwordInputObserver = new MutationObserver(() => {
    addPasswordInputListeners();
});

passwordInputObserver.observe(document.body, {
    childList: true,
    subtree: true
});

// Add MutationObserver to detect dynamically added password inputs
const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
            if (node.nodeType === 1) { // Element node
                if (node.tagName === 'INPUT' && node.type === 'password') {
                    console.log('New password input detected:', node);
                }
                // Check child nodes
                const passwordInputs = node.querySelectorAll('input[type="password"]');
                passwordInputs.forEach(input => {
                    console.log('Password input in new content:', input);
                });
            }
        });
    });
});

observer.observe(document.body, {
    childList: true,
    subtree: true
});
