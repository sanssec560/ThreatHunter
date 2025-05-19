// Main JavaScript for Threat Hunting App

document.addEventListener('DOMContentLoaded', function() {
    // Initialize test connection button in navbar
    const testConnectionBtn = document.getElementById('test-connection-btn');
    if (testConnectionBtn) {
        testConnectionBtn.addEventListener('click', function() {
            testSplunkConnection();
        });
    }
    
    // Auto-resize textareas
    const textareas = document.querySelectorAll('textarea');
    textareas.forEach(textarea => {
        autoResizeTextarea(textarea);
        textarea.addEventListener('input', function() {
            autoResizeTextarea(this);
        });
    });
});

/**
 * Test Splunk connection using the API
 */
function testSplunkConnection() {
    // Show loading state
    const testConnectionBtn = document.getElementById('test-connection-btn');
    const originalText = testConnectionBtn.innerHTML;
    testConnectionBtn.disabled = true;
    testConnectionBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';
    
    // Send test connection request
    fetch('/test-connection', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        // Show result
        const alertClass = data.success ? 'success' : 'danger';
        const alertIcon = data.success ? 'check-circle' : 'exclamation-triangle';
        
        // Create alert
        const alert = document.createElement('div');
        alert.className = `alert alert-${alertClass} alert-dismissible fade show`;
        alert.innerHTML = `
            <i class="fas fa-${alertIcon}"></i> ${data.message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Add alert to the top of the main content
        const main = document.querySelector('main');
        main.insertBefore(alert, main.firstChild);
        
        // Auto-dismiss alert after 5 seconds
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
        
        // Reset button state
        testConnectionBtn.disabled = false;
        testConnectionBtn.innerHTML = originalText;
    })
    .catch(error => {
        // Show error
        const alert = document.createElement('div');
        alert.className = 'alert alert-danger alert-dismissible fade show';
        alert.innerHTML = `
            <i class="fas fa-exclamation-triangle"></i> Error testing connection: ${error.message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Add alert to the top of the main content
        const main = document.querySelector('main');
        main.insertBefore(alert, main.firstChild);
        
        // Auto-dismiss alert after 5 seconds
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
        
        // Reset button state
        testConnectionBtn.disabled = false;
        testConnectionBtn.innerHTML = originalText;
    });
}

/**
 * Auto-resize textarea based on content
 * @param {HTMLTextAreaElement} textarea - The textarea element to resize
 */
function autoResizeTextarea(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = (textarea.scrollHeight) + 'px';
}

/**
 * Format JSON for display
 * @param {string} json - JSON string to format
 * @returns {string} - Formatted HTML
 */
function formatJSON(json) {
    try {
        const obj = JSON.parse(json);
        return JSON.stringify(obj, null, 2);
    } catch (e) {
        return json;
    }
}

/**
 * Truncate text with ellipsis
 * @param {string} text - Text to truncate
 * @param {number} length - Maximum length
 * @returns {string} - Truncated text
 */
function truncateText(text, length = 100) {
    if (text.length <= length) {
        return text;
    }
    return text.substring(0, length) + '...';
}
