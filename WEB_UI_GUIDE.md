# AudeSec Web UI Guide

## Overview

The AudeSec Web UI provides a user-friendly interface for running security scans on Git repositories with real-time progress updates and comprehensive metrics visualization.

## Features

✨ **Key Features:**
- 🌐 Web-based interface - no command line needed
- 🔄 Real-time progress updates via WebSocket
- 📊 Visual metrics dashboard showing security improvements
- 🎯 Step-by-step workflow visualization
- 📱 Responsive design - works on desktop and mobile
- 🚀 Background processing - scan runs asynchronously

## Architecture

```
┌─────────────────┐
│   Web Browser   │
│   (Frontend)    │
└────────┬────────┘
         │ HTTP/WebSocket
         ▼
┌─────────────────┐
│  Flask Server   │
│  (web_app.py)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Security Scan  │
│   Workflow      │
│  (Background)   │
└─────────────────┘
```

## Installation

### 1. Install Dependencies

```bash
cd audesec-poc
pip install -r requirements.txt
```

### 2. Configure Environment

Ensure your `.env` file has the required credentials:

```bash
# OpenAI API Key (required)
OPENAI_API_KEY=your_openai_api_key

# GitHub Token (required for private repos)
GITHUB_TOKEN=your_github_token

# JIRA Configuration (optional)
JIRA_URL=https://your-domain.atlassian.net
JIRA_EMAIL=your-email@example.com
JIRA_API_TOKEN=your_jira_api_token
JIRA_PROJECT_KEY=SEC
```

### 3. Verify Prerequisites

Make sure you have:
- ✅ Docker installed and running
- ✅ Trivy installed (`brew install trivy` on macOS)
- ✅ Git installed
- ✅ GitHub CLI installed (optional, for PR creation)

## Running the Web UI

### Start the Server

```bash
python web_app.py
```

The server will start on `http://localhost:5000`

### Access the UI

Open your browser and navigate to:
```
http://localhost:5000
```

## Using the Web UI

### Step 1: Enter Repository URL

1. On the home page, enter your Git repository URL
2. Format: `https://github.com/username/repository.git`
3. Click "Start Scan"

### Step 2: Monitor Progress

The UI will show real-time progress through 15 steps:

| Step | Description | Icon |
|------|-------------|------|
| 0 | Cleanup | 🧹 |
| 1 | Configuration | ⚙️ |
| 2 | Clone Repository | 📥 |
| 3 | File Discovery | 🔍 |
| 4 | Kubernetes Scan | ☸️ |
| 5 | Container Scan | 🐳 |
| 6 | Combine Findings | 📊 |
| 7 | JIRA Tickets | 🎫 |
| 8 | AI Remediation | 🤖 |
| 9 | Apply Fixes | ✏️ |
| 10 | Validation | ✅ |
| 11 | Dockerfile Update | 🔧 |
| 12 | Rebuild Container | 🔨 |
| 13 | Re-scan | 🔄 |
| 14 | Metrics | 📈 |

Each step shows:
- ⏳ Running (yellow background)
- ✅ Success (green background)
- ❌ Error (red background)
- ℹ️ Info (blue background)

### Step 3: View Results

After completion, the UI displays:

**Total Issues:**
- Before/After comparison
- Number of issues fixed
- Improvement percentage

**Kubernetes Issues:**
- Misconfigurations found and fixed
- Improvement metrics

**CVE Vulnerabilities:**
- Container image vulnerabilities
- Base image updates
- Security improvements

## API Endpoints

### POST /api/scan

Start a new security scan.

**Request:**
```json
{
  "repo_url": "https://github.com/username/repo.git"
}
```

**Response:**
```json
{
  "scan_id": "scan_20260516_103000",
  "status": "started",
  "message": "Security scan started"
}
```

### GET /api/scan/{scan_id}

Get the status and results of a scan.

**Response:**
```json
{
  "status": "complete",
  "steps": [...],
  "metrics": {
    "total": {...},
    "kubernetes": {...},
    "cve": {...}
  }
}
```

## WebSocket Events

### Client → Server

**join_scan:**
```javascript
socket.emit('join_scan', { scan_id: 'scan_20260516_103000' });
```

### Server → Client

**progress_update:**
```javascript
{
  "scan_id": "scan_20260516_103000",
  "step": 4,
  "status": "success",
  "message": "Found 20 Kubernetes issues",
  "timestamp": "2026-05-16T10:30:00",
  "data": { "count": 20 }
}
```

## Customization

### Modify Scan Steps

Edit `web_app.py` to add/remove steps in the `run_security_scan()` function.

### Update UI Styling

Edit `static/css/style.css` to customize colors, fonts, and layout.

### Add New Metrics

Update the metrics calculation in step 14 and add corresponding UI elements in `templates/index.html`.

## Troubleshooting

### Port Already in Use

If port 5000 is already in use:

```python
# In web_app.py, change the port:
socketio.run(app, debug=True, host='0.0.0.0', port=5001)
```

### WebSocket Connection Failed

1. Check if the server is running
2. Verify firewall settings
3. Try disabling browser extensions
4. Check browser console for errors

### Scan Stuck on a Step

1. Check server logs for errors
2. Verify Docker is running
3. Ensure Trivy is installed
4. Check network connectivity

### Validation Errors

If validation fails:
1. Check the AI output in server logs
2. Verify OpenAI API key is valid
3. Review the cleaning functions in `agents/remediation.py`

## Production Deployment

### Using Gunicorn

```bash
pip install gunicorn
gunicorn -k eventlet -w 1 -b 0.0.0.0:5000 web_app:app
```

### Using Docker

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["gunicorn", "-k", "eventlet", "-w", "1", "-b", "0.0.0.0:5000", "web_app:app"]
```

Build and run:

```bash
docker build -t audesec-web .
docker run -p 5000:5000 --env-file .env audesec-web
```

### Environment Variables

For production, set:

```bash
export FLASK_ENV=production
export SECRET_KEY=your-secure-random-key
```

### Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name audesec.example.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Considerations

1. **Authentication:** Add user authentication for production use
2. **Rate Limiting:** Implement rate limiting to prevent abuse
3. **Input Validation:** Validate repository URLs before processing
4. **Secret Management:** Use environment variables for sensitive data
5. **HTTPS:** Always use HTTPS in production
6. **CORS:** Configure CORS properly for your domain

## Performance Tips

1. **Concurrent Scans:** Limit concurrent scans to avoid resource exhaustion
2. **Caching:** Cache scan results for frequently scanned repositories
3. **Cleanup:** Implement automatic cleanup of old scan results
4. **Resource Limits:** Set Docker resource limits for container builds
5. **Database:** Consider using a database for persistent storage

## Future Enhancements

- [ ] User authentication and authorization
- [ ] Scan history and comparison
- [ ] Scheduled scans
- [ ] Email notifications
- [ ] Slack/Teams integration
- [ ] Custom scan configurations
- [ ] Multi-repository scanning
- [ ] Export reports (PDF, CSV)
- [ ] API rate limiting
- [ ] Scan queue management

## Support

For issues or questions:
1. Check the logs in the terminal
2. Review the browser console for frontend errors
3. Verify all prerequisites are installed
4. Check the main README.md for general setup

## License

Same as the main project.