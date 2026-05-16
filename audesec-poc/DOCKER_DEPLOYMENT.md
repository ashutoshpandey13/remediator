# Docker Deployment Guide for AudeSec

Complete guide for deploying AudeSec Security Remediation Platform using Docker.

## 📋 Prerequisites

- Docker Engine 20.10+ installed
- At least 4GB RAM available
- 10GB free disk space

## 🚀 Quick Start (Docker)

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd audesec-poc
```

### 2. Build the Docker Image

```bash
docker build -t audesec-platform .
```

### 3. Run the Container

```bash
docker run -d \
  --name audesec \
  -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/fixed:/app/fixed \
  -e OPENAI_API_KEY=your_openai_api_key_here \
  -e GITHUB_TOKEN=your_github_token_here \
  audesec-platform
```

### 4. Access the Application

Open your browser and navigate to:
```
http://localhost:8000
```

### 5. View Logs

```bash
docker logs -f audesec
```

### 6. Stop the Container

```bash
docker stop audesec
docker rm audesec
```

## 🐳 Docker Commands Reference

### Build Image

```bash
docker build -t audesec-platform .

# Build with no cache
docker build --no-cache -t audesec-platform .

# Build with custom tag
docker build -t audesec-platform:v1.0 .
```

### Run Container

**Basic run:**
```bash
docker run -d \
  --name audesec \
  -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e OPENAI_API_KEY=your_key \
  -e GITHUB_TOKEN=your_token \
  audesec-platform
```

**With all options:**
```bash
docker run -d \
  --name audesec \
  -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/fixed:/app/fixed \
  -e OPENAI_API_KEY=your_key \
  -e GITHUB_TOKEN=your_token \
  -e JIRA_URL=https://your-domain.atlassian.net \
  -e JIRA_EMAIL=your@email.com \
  -e JIRA_API_TOKEN=your_jira_token \
  -e JIRA_PROJECT=SEC \
  --restart unless-stopped \
  --memory="4g" \
  --cpus="2.0" \
  audesec-platform
```

### Manage Container

```bash
# View logs
docker logs -f audesec

# View logs (last 100 lines)
docker logs --tail 100 audesec

# Stop container
docker stop audesec

# Start stopped container
docker start audesec

# Restart container
docker restart audesec

# Remove container
docker rm audesec

# Force remove running container
docker rm -f audesec
```

### Inspect Container

```bash
# View container details
docker inspect audesec

# View container stats
docker stats audesec

# Execute command in container
docker exec -it audesec bash

# Check health status
docker inspect --format='{{.State.Health.Status}}' audesec
```

### Clean Up

```bash
# Stop and remove container
docker stop audesec && docker rm audesec

# Remove image
docker rmi audesec-platform

# Remove all stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Full cleanup (WARNING: removes all unused Docker resources)
docker system prune -a --volumes
```

## 📁 Volume Mounts

The container uses the following volumes:

| Host Path | Container Path | Purpose |
|-----------|---------------|---------|
| `/var/run/docker.sock` | `/var/run/docker.sock` | Docker socket for building images |
| `./reports` | `/app/reports` | Scan reports persistence |
| `./fixed` | `/app/fixed` | Fixed files persistence |

## 🔧 Configuration

### Port Configuration

To change the port, update both:

1. **docker-compose.yml:**
```yaml
ports:
  - "9000:8000"  # Host:Container
```

2. **.env file:**
```env
PORT=8000  # Keep container port same
```

### Resource Limits

Add resource limits in `docker-compose.yml`:

```yaml
services:
  audesec-web:
    # ... other config
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
```

## 🔒 Security Considerations

### 1. Non-Root User

The container runs as a non-root user (`audesec`) for security.

### 2. Docker Socket Access

The container needs access to Docker socket to build images. This is required for:
- Building container images during scans
- Scanning images with Trivy

**Security Note:** Mounting Docker socket gives the container significant privileges. Only use in trusted environments.

### 3. Environment Variables

Never commit `.env` file to version control. Use secrets management in production:

```bash
# Example with Docker secrets
docker secret create openai_key openai_key.txt
```

## 🏗️ Production Deployment

### Using Docker Swarm

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml audesec
```

### Using Kubernetes

Create a deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: audesec-platform
spec:
  replicas: 2
  selector:
    matchLabels:
      app: audesec
  template:
    metadata:
      labels:
        app: audesec
    spec:
      containers:
      - name: audesec
        image: audesec-platform:latest
        ports:
        - containerPort: 8000
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: audesec-secrets
              key: openai-key
        volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
      volumes:
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
```

### Behind Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name audesec.example.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 🐛 Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs audesec-web

# Common issues:
# 1. Port already in use
sudo lsof -i :8000

# 2. Docker socket permission
sudo chmod 666 /var/run/docker.sock

# 3. Missing environment variables
docker-compose config
```

### Can't Build Images Inside Container

```bash
# Verify Docker socket is mounted
docker exec audesec-web ls -la /var/run/docker.sock

# Test Docker access
docker exec audesec-web docker ps
```

### Trivy Not Working

```bash
# Update Trivy database
docker exec audesec-web trivy image --download-db-only

# Test Trivy
docker exec audesec-web trivy --version
```

### Out of Memory

```bash
# Check container stats
docker stats audesec-web

# Increase memory limit in docker-compose.yml
```

## 📊 Monitoring

### Health Check

```bash
# Check health status
docker inspect --format='{{.State.Health.Status}}' audesec-web

# Manual health check
curl http://localhost:8000/
```

### Resource Usage

```bash
# Real-time stats
docker stats audesec-web

# Detailed info
docker inspect audesec-web
```

## 🔄 Updates

### Update Application

```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Update Dependencies

```bash
# Update requirements.txt
# Then rebuild
docker-compose build --no-cache
```

## 🧹 Cleanup

### Remove Everything

```bash
# Stop and remove containers
docker-compose down

# Remove images
docker rmi audesec-platform

# Remove volumes (WARNING: deletes data)
docker-compose down -v

# Clean up Docker system
docker system prune -a
```

## 📝 Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | 8000 | Application port |
| `OPENAI_API_KEY` | Yes | - | OpenAI API key for AI remediation |
| `GITHUB_TOKEN` | Yes | - | GitHub token for repository access |
| `JIRA_URL` | No | - | JIRA instance URL |
| `JIRA_EMAIL` | No | - | JIRA user email |
| `JIRA_API_TOKEN` | No | - | JIRA API token |
| `JIRA_PROJECT` | No | SEC | JIRA project key |

## 🎯 Best Practices

1. **Use Docker Compose** for local development
2. **Use orchestration** (Swarm/Kubernetes) for production
3. **Mount volumes** for data persistence
4. **Set resource limits** to prevent resource exhaustion
5. **Use secrets management** for sensitive data
6. **Enable health checks** for monitoring
7. **Regular updates** for security patches
8. **Backup volumes** regularly

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Flask Deployment](https://flask.palletsprojects.com/en/2.3.x/deploying/)

## 🆘 Support

For issues or questions:
1. Check the logs: `docker-compose logs -f`
2. Review this guide
3. Check the main README.md
4. Open an issue on GitHub