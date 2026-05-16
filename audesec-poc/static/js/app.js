// DOM elements
const scanForm = document.getElementById('scanForm');
const repoUrlInput = document.getElementById('repoUrl');
const startScanBtn = document.getElementById('startScanBtn');
const scanProgress = document.getElementById('scanProgress');
const scanResults = document.getElementById('scanResults');
const currentScanIdSpan = document.getElementById('currentScanId');

let currentScanId = null;
let pollInterval = null;

// Form submission
scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const repoUrl = repoUrlInput.value.trim();
    if (!repoUrl) {
        alert('Please enter a repository URL');
        return;
    }
    
    // Disable form
    startScanBtn.disabled = true;
    startScanBtn.querySelector('.btn-text').textContent = 'Starting...';
    startScanBtn.querySelector('.btn-loader').style.display = 'inline-block';
    
    try {
        // Start scan
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ repo_url: repoUrl })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentScanId = data.scan_id;
            currentScanIdSpan.textContent = currentScanId;
            
            // Show progress section
            scanProgress.style.display = 'block';
            scanResults.style.display = 'none';
            
            // Scroll to progress
            scanProgress.scrollIntoView({ behavior: 'smooth' });
            
            // Reset all steps
            resetSteps();
            
            // Start polling for updates
            startPolling();
        } else {
            alert('Error: ' + data.error);
            resetForm();
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        alert('Failed to start scan. Please try again.');
        resetForm();
    }
});

function startPolling() {
    // Poll every 2 seconds
    pollInterval = setInterval(async () => {
        try {
            const response = await fetch(`/api/scan/${currentScanId}`);
            const data = await response.json();
            
            if (data.steps && data.steps.length > 0) {
                // Update UI with latest steps
                data.steps.forEach(progress => {
                    updateStep(progress);
                });
                
                // Check if scan is complete
                if (data.status === 'complete' && data.metrics) {
                    clearInterval(pollInterval);
                    setTimeout(() => {
                        showResults(data.metrics);
                    }, 1000);
                } else if (data.status === 'error') {
                    clearInterval(pollInterval);
                    alert('Scan failed: ' + (data.error || 'Unknown error'));
                    setTimeout(() => {
                        resetForm();
                    }, 2000);
                }
            }
        } catch (error) {
            console.error('Polling error:', error);
        }
    }, 2000);
}

function updateStep(progress) {
    const step = progress.step;
    const status = progress.status;
    const message = progress.message;
    const data = progress.data;
    
    // Find the step element
    const stepElement = document.querySelector(`.step[data-step="${step}"]`);
    if (!stepElement) return;
    
    // Remove all status classes
    stepElement.classList.remove('running', 'success', 'error', 'info');
    
    // Add current status class
    stepElement.classList.add(status);
    
    // Update message
    const messageElement = stepElement.querySelector('.step-message');
    messageElement.textContent = message;
    
    // Add data details if available
    if (data) {
        const dataText = formatStepData(step, data);
        if (dataText) {
            messageElement.textContent += ' ' + dataText;
        }
    }
    
    // Update status icon
    const statusElement = stepElement.querySelector('.step-status');
    switch (status) {
        case 'running':
            statusElement.textContent = '⏳';
            break;
        case 'success':
            statusElement.textContent = '✅';
            break;
        case 'error':
            statusElement.textContent = '❌';
            break;
        case 'info':
            statusElement.textContent = 'ℹ️';
            break;
    }
    
    // Scroll to current step
    stepElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function formatStepData(step, data) {
    switch (step) {
        case 1:
            return data.repo_name ? `(${data.repo_name})` : '';
        case 3:
            return data.files ? `(${data.files.join(', ')})` : '';
        case 4:
            return data.count !== undefined ? `(${data.count} issues)` : '';
        case 5:
            return data.cve_count !== undefined ? `(${data.cve_count} CVEs)` : '';
        case 6:
            return (data.k8s !== undefined && data.cve !== undefined) ? `(K8s: ${data.k8s}, CVE: ${data.cve})` : '';
        case 7:
            return data.tickets ? `(${data.tickets.join(', ')})` : '';
        case 9:
            return data.files ? `(${data.files.join(', ')})` : '';
        case 12:
            return data.new_cve_count !== undefined ? `(${data.new_cve_count} CVEs remaining)` : '';
        case 13:
            return (data.new_k8s_count !== undefined && data.new_cve_count !== undefined) ? `(K8s: ${data.new_k8s_count}, CVE: ${data.new_cve_count})` : '';
        default:
            return '';
    }
}

function showResults(metrics) {
    // Hide progress, show results
    scanProgress.style.display = 'none';
    scanResults.style.display = 'block';
    
    // Update metrics
    if (metrics) {
        // Total
        document.getElementById('totalBefore').textContent = metrics.total.before;
        document.getElementById('totalAfter').textContent = metrics.total.after;
        document.getElementById('totalFixed').textContent = metrics.total.fixed;
        document.getElementById('totalPercent').textContent = metrics.total.improvement + '%';
        
        // Kubernetes
        document.getElementById('k8sBefore').textContent = metrics.kubernetes.before;
        document.getElementById('k8sAfter').textContent = metrics.kubernetes.after;
        document.getElementById('k8sFixed').textContent = metrics.kubernetes.fixed;
        document.getElementById('k8sPercent').textContent = metrics.kubernetes.improvement + '%';
        
        // CVE
        document.getElementById('cveBefore').textContent = metrics.cve.before;
        document.getElementById('cveAfter').textContent = metrics.cve.after;
        document.getElementById('cveFixed').textContent = metrics.cve.fixed;
        document.getElementById('cvePercent').textContent = metrics.cve.improvement + '%';
    }
    
    // Scroll to results
    scanResults.scrollIntoView({ behavior: 'smooth' });
    
    // Reset form
    resetForm();
}

function resetSteps() {
    const steps = document.querySelectorAll('.step');
    steps.forEach(step => {
        step.classList.remove('running', 'success', 'error', 'info');
        const statusElement = step.querySelector('.step-status');
        statusElement.textContent = '⏳';
        
        // Reset message to default
        const stepNum = parseInt(step.dataset.step);
        const messageElement = step.querySelector('.step-message');
        messageElement.textContent = getDefaultMessage(stepNum);
    });
}

function getDefaultMessage(step) {
    const messages = {
        0: 'Preparing environment...',
        1: 'Loading repository configuration...',
        2: 'Cloning repository...',
        3: 'Discovering files...',
        4: 'Scanning Kubernetes configurations...',
        5: 'Building and scanning container image...',
        6: 'Analyzing security findings...',
        7: 'Creating tracking tickets...',
        8: 'Generating fixes with AI...',
        9: 'Applying security fixes...',
        10: 'Validating fixed files...',
        11: 'Updating Dockerfile...',
        12: 'Rebuilding container image...',
        13: 'Re-scanning fixed assets...',
        14: 'Calculating improvement metrics...'
    };
    return messages[step] || 'Processing...';
}

function resetForm() {
    startScanBtn.disabled = false;
    startScanBtn.querySelector('.btn-text').textContent = 'Start Scan';
    startScanBtn.querySelector('.btn-loader').style.display = 'none';
}
