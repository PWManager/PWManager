document.addEventListener('DOMContentLoaded', async () => {
    const statusDiv = document.getElementById('status');
    const passwordList = document.getElementById('passwordList');
    const generateButton = document.getElementById('generateButton');
    const copyButton = document.getElementById('copyButton');
    const generatedPassword = document.getElementById('generatedPassword');
    
    // Function to generate password
    function generatePassword(length, useUppercase, useLowercase, useNumbers, useSpecial) {
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const numbers = '0123456789';
        const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        let chars = '';
        if (useUppercase) chars += uppercase;
        if (useLowercase) chars += lowercase;
        if (useNumbers) chars += numbers;
        if (useSpecial) chars += special;
        
        if (chars === '') {
            alert('Please select at least one character type');
            return null;
        }
        
        let password = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * chars.length);
            password += chars[randomIndex];
        }
        
        return password;
    }
    
    // Check connection status
    async function checkConnection() {
        const statusElement = document.getElementById('status');
        
        try {
            const response = await fetch('http://localhost:8080/passwords', {
                headers: { 'Accept': 'application/json' },
                mode: 'cors'
            });
            
            if (response.ok) {
                statusElement.textContent = 'Connected to PWManager';
                statusElement.className = 'status connected';
                return true;
            } else {
                throw new Error('Server error');
            }
        } catch (error) {
            statusElement.textContent = 'Not connected to PWManager';
            statusElement.className = 'status disconnected';
            return false;
        }
    }
    
    // Load passwords
    async function loadPasswords() {
        const passwordsContainer = document.getElementById('passwords');
        
        try {
            const response = await fetch('http://localhost:8080/passwords', {
                headers: { 'Accept': 'application/json' },
                mode: 'cors'
            });
            
            if (!response.ok) {
                throw new Error('Failed to fetch passwords');
            }
            
            const passwords = await response.json();
            
            // Clear existing passwords
            passwordsContainer.innerHTML = '';
            
            // Add each password
            Object.entries(passwords).forEach(([site, password]) => {
                const item = document.createElement('div');
                item.className = 'password-item';
                item.innerHTML = `
                    <div class="site-name">${site}</div>
                    <div class="password-text">${password}</div>
                `;
                
                // Copy password on click
                item.addEventListener('click', () => {
                    navigator.clipboard.writeText(password).then(() => {
                        // Visual feedback
                        item.style.background = '#4CAF50';
                        setTimeout(() => {
                            item.style.background = '';
                        }, 200);
                    });
                });
                
                passwordsContainer.appendChild(item);
            });
        } catch (error) {
            passwordsContainer.innerHTML = `
                <div class="password-item">
                    <div class="site-name">Error</div>
                    <div class="password-text">Failed to load passwords</div>
                </div>
            `;
        }
    }
    
    // Generate password button click handler
    generateButton.addEventListener('click', () => {
        const length = parseInt(document.getElementById('passwordLength').value);
        const useUppercase = document.getElementById('useUppercase').checked;
        const useLowercase = document.getElementById('useLowercase').checked;
        const useNumbers = document.getElementById('useNumbers').checked;
        const useSpecial = document.getElementById('useSpecial').checked;
        
        const password = generatePassword(length, useUppercase, useLowercase, useNumbers, useSpecial);
        if (password) {
            generatedPassword.textContent = password;
            generatedPassword.style.display = 'block';
            copyButton.style.display = 'block';
        }
    });
    
    // Copy button click handler
    copyButton.addEventListener('click', () => {
        const password = generatedPassword.textContent;
        navigator.clipboard.writeText(password).then(() => {
            copyButton.textContent = 'Copied!';
            setTimeout(() => {
                copyButton.textContent = 'Copy to Clipboard';
            }, 2000);
        });
    });
    
    // Check connection first
    const isConnected = await checkConnection();
    
    if (isConnected) {
        // Load passwords if connected
        await loadPasswords();
    }
}); 