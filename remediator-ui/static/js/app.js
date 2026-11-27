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
                        showResults(data.metrics, data);
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
    
    // Find the step element. A fatal error (step -1) has no row of its own,
    // so show it on the step that was running, or the first step if none was.
    let stepElement = document.querySelector(`.step[data-step="${step}"]`);
    if (!stepElement && step === -1) {
        const running = document.querySelectorAll('.step.running');
        stepElement = running.length
            ? running[running.length - 1]
            : document.querySelector('.step');
    }
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
    // The server sends a ready-made summary in `detail` for every step
    return data && typeof data.detail === 'string' ? data.detail : '';
}

const METRIC_CARDS = [
    { key: 'total', title: 'Total Issues', icon: '🎯', cls: 'total' },
    { key: 'kubernetes', title: 'Kubernetes Issues', icon: '☸️', cls: 'k8s' },
    { key: 'cve', title: 'CVE Vulnerabilities', icon: '🔒', cls: 'cve' },
    { key: 'sast', title: 'Code Vulnerabilities (SAST)', icon: '🧬', cls: 'sast' },
    { key: 'secrets', title: 'Hardcoded Secrets', icon: '🔑', cls: 'secrets' }
];

const ADVISORY_CARDS = [
    { key: 'cspm', title: 'Cloud Posture (IaC)', icon: '☁️' }
];

function createEl(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
}

function createMetricBox(label, value, className) {
    const box = createEl('div', className);
    box.appendChild(createEl('span', 'label', label));
    box.appendChild(createEl('span', 'value', value));
    return box;
}

function createMetricCard(def, metric) {
    const card = createEl('div', 'metric-card ' + def.cls);

    const header = createEl('div', 'metric-header');
    header.appendChild(createEl('h3', null, def.title));
    header.appendChild(createEl('div', 'metric-icon', def.icon));
    card.appendChild(header);

    const body = createEl('div', 'metric-body');

    const comparison = createEl('div', 'metric-comparison');
    comparison.appendChild(createMetricBox('Before', metric.before, 'metric-before'));
    comparison.appendChild(createEl('div', 'metric-arrow', '→'));
    comparison.appendChild(createMetricBox('After', metric.after, 'metric-after'));
    body.appendChild(comparison);

    const improvement = createEl('div', 'metric-improvement');
    improvement.appendChild(createEl('span', 'improvement-label', 'Fixed:'));
    improvement.appendChild(createEl('span', 'improvement-value', metric.fixed));
    improvement.appendChild(createEl('span', 'improvement-percent', metric.improvement + '%'));
    body.appendChild(improvement);

    card.appendChild(body);
    return card;
}

function createAdvisoryCard(def, count) {
    const card = createEl('div', 'advisory-card');
    card.appendChild(createEl('div', 'advisory-icon', def.icon));
    card.appendChild(createEl('div', 'advisory-count', count));
    card.appendChild(createEl('div', 'advisory-title', def.title));
    return card;
}

const JIRA_KEY_PATTERN = /^[A-Z][A-Z0-9_]+-\d+$/;

// Returns the normalised URL only for plain https links without embedded credentials
function safeHttpsUrl(value) {
    if (typeof value !== 'string' || !value.startsWith('https://') || /[\s\u0000-\u001f\u007f]/.test(value)) {
        return null;
    }
    try {
        const parsed = new URL(value);
        if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password) {
            return null;
        }
        return parsed.href;
    } catch (e) {
        return null;
    }
}

function jiraBrowseUrl(baseUrl, key) {
    const base = safeHttpsUrl(baseUrl);
    if (!base || typeof key !== 'string' || !JIRA_KEY_PATTERN.test(key)) return null;
    return safeHttpsUrl(base.replace(/\/+$/, '') + '/browse/' + encodeURIComponent(key));
}

function createExternalLink(href, text) {
    const link = createEl('a', null, text);
    link.href = href;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    return link;
}

function createDeliveryBlock(title, warn) {
    const block = createEl('div', 'delivery-block' + (warn ? ' warn' : ''));
    block.appendChild(createEl('h4', null, title));
    return block;
}

function createList(items) {
    const list = createEl('ul', 'delivery-list');
    items.forEach(item => list.appendChild(item));
    return list;
}

function createPullRequestBlock(result) {
    const prUrl = safeHttpsUrl(result.pr_url);
    const block = createDeliveryBlock('Pull Request', !prUrl);

    if (prUrl) {
        const line = createEl('p');
        line.appendChild(createExternalLink(prUrl, prUrl));
        block.appendChild(line);
    } else {
        // pr_status: no_changes, no_token, unsupported_host, commit_failed, push_failed, failed
        const message = typeof result.pr_message === 'string' && result.pr_message
            ? result.pr_message
            : 'No pull request was raised.';
        block.appendChild(createEl('p', null, message));
    }

    if (typeof result.default_branch === 'string' && result.default_branch) {
        block.appendChild(createEl('p', null, 'Base branch: ' + result.default_branch));
    }

    const files = Array.isArray(result.files_updated) ? result.files_updated : [];
    if (files.length) {
        block.appendChild(createEl('p', null, 'Files updated (' + files.length + '):'));
        block.appendChild(createList(files.map(file => {
            const item = createEl('li');
            item.appendChild(createEl('code', null, String(file)));
            return item;
        })));
    }
    return block;
}

function createJiraBlock(result) {
    const keys = Array.isArray(result.jira_keys) ? result.jira_keys : [];
    const links = result.jira_links && typeof result.jira_links === 'object' ? result.jira_links : {};
    const block = createDeliveryBlock('JIRA Tickets', false);

    if (!keys.length) {
        block.appendChild(createEl('p', null, 'No JIRA tickets were created.'));
    } else {
        block.appendChild(createList(keys.map(key => {
            const item = createEl('li');
            const url = jiraBrowseUrl(result.jira_base_url, key);
            if (url) {
                item.appendChild(createExternalLink(url, String(key)));
            } else {
                item.appendChild(createEl('span', null, String(key)));
            }
            if (Object.prototype.hasOwnProperty.call(links, key)) {
                const linked = links[key] === true;
                item.appendChild(createEl(
                    'span',
                    linked ? 'link-ok' : 'link-failed',
                    linked ? ' - pull request linked' : ' - pull request link failed'
                ));
            }
            return item;
        })));
    }

    if (typeof result.jira_link_message === 'string' && result.jira_link_message) {
        block.appendChild(createEl('p', null, result.jira_link_message));
    }
    return block;
}

function showDelivery(result) {
    const body = document.getElementById('deliveryBody');
    body.replaceChildren();
    body.appendChild(createPullRequestBlock(result || {}));
    body.appendChild(createJiraBlock(result || {}));
}

function showResults(metrics, result) {
    // Hide progress, show results
    scanProgress.style.display = 'none';
    scanResults.style.display = 'block';

    const grid = document.getElementById('metricsGrid');
    const advisorySection = document.getElementById('advisorySection');
    const advisoryGrid = document.getElementById('advisoryGrid');

    grid.replaceChildren();
    advisoryGrid.replaceChildren();
    advisorySection.style.display = 'none';

    if (metrics) {
        // Scanners that could not run have no entry in metrics and are skipped
        METRIC_CARDS.forEach(def => {
            if (metrics[def.key]) {
                grid.appendChild(createMetricCard(def, metrics[def.key]));
            }
        });

        if (metrics.advisory) {
            let any = false;
            ADVISORY_CARDS.forEach(def => {
                const count = metrics.advisory[def.key];
                if (count) {
                    any = true;
                    advisoryGrid.appendChild(createAdvisoryCard(def, count));
                }
            });
            if (any) advisorySection.style.display = 'block';
        }
    }

    showDelivery(result);

    // Scroll to results
    scanResults.scrollIntoView({ behavior: 'smooth' });

    // Reset form
    resetForm();
}

function resetSteps() {
    const steps = document.querySelectorAll('.step');
    steps.forEach(step => {
        step.classList.remove('running', 'success', 'error', 'info');
        step.querySelector('.step-status').textContent = '⏳';
        step.querySelector('.step-message').textContent = step.dataset.defaultMessage || 'Processing...';
    });
}

function resetForm() {
    startScanBtn.disabled = false;
    startScanBtn.querySelector('.btn-text').textContent = 'Start Scan';
    startScanBtn.querySelector('.btn-loader').style.display = 'none';
}
