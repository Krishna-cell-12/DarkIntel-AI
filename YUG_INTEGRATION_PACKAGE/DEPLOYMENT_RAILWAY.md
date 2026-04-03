# Railway Deployment Guide

## Prerequisites

1. Railway.app account (free tier available)
2. GitHub repository with code
3. Docker installed (for local testing)

## Quick Deploy Steps

### 1. Connect GitHub to Railway

```bash
# Go to https://railway.app/dashboard
# Click "New Project" → "Deploy from GitHub"
# Select this repository
# Railway auto-detects Dockerfile.backend
```

### 2. Set Environment Variables

In Railway dashboard, go to `Variables` and add:

```
DEMO_MODE=true
TOR_ENABLED=false
CORS_ORIGINS=*
LOG_LEVEL=INFO

# Optional - Add your API keys
# GROQ_API_KEY=your_key
# ALCHEMY_API_KEY=your_key
# ETHERSCAN_API_KEY=your_key
```

### 3. Configure Domain

- Railway auto-generates a URL like: `darkintel-api-prod.up.railway.app`
- Add custom domain if preferred
- CORS already configured for all origins

### 4. Deploy

```bash
# Method 1: Push to GitHub (auto-deploy)
git push origin main

# Method 2: Deploy via Railway CLI
railway login
railway link
railway up
```

### 5. Monitor Deployment

- Check Railway dashboard for build logs
- Monitor application logs
- Health check API: `https://darkintel-api-prod.up.railway.app/health`

## Testing Deployment

```bash
# Replace with your Railway URL
BASE_URL="https://darkintel-api-prod.up.railway.app"

# Test health check
curl $BASE_URL/health

# Test demo dashboard
curl $BASE_URL/demo/dashboard

# Test Swagger docs
# Open in browser: $BASE_URL/docs
```

## Troubleshooting

### Build Fails

```
Check:
1. Dockerfile.backend exists
2. requirements.txt has all dependencies
3. No syntax errors in Python
4. RAM/timeout not exceeded (free tier: 5min build timeout)
```

### App Crashes

```
Check Railway logs for:
- ImportError: Missing dependencies
- AttributeError: Module not found
- Port binding error (should be 8000)

Common fixes:
1. Rebuild: railway up --build
2. Update requirements.txt
3. Check Dockerfile syntax
```

### Slow Response

```
Solutions:
1. Enable Redis caching (add service in Railway)
2. Use demo_mode=true (cached responses)
3. Scale up RAM (Railway dashboard)
4. Add more instances
```

## Advanced Configuration

### Add Redis Cache

```bash
# In Railway dashboard:
# 1. New Service → Add Service
# 2. Database → Redis
# 3. Set REDIS_URL to connection string
```

### Add PostgreSQL Database

```bash
# Replace SQLite with PostgreSQL:
# 1. New Service → Add Service
# 2. Database → PostgreSQL
# 3. Update DATABASE_URL in variables
```

### Monitor Performance

```bash
# Install railway CLI
npm install -g @railway/cli

# View logs
railway logs

# Monitor resource usage
railway status
```

## Pricing

- **Free Tier**: $5/month free, then pay-as-you-go
- **Current Project**: ~$0-2/month (minimal usage)
- **With Database**: +$5-10/month for PostgreSQL
- **With Redis**: +$2/month

## Deployment Checklist

- [ ] GitHub repo connected to Railway
- [ ] Dockerfile.backend works locally
- [ ] Environment variables set
- [ ] Health check passes
- [ ] Demo endpoints respond
- [ ] API docs accessible at /docs
- [ ] CORS configured correctly
- [ ] Logs are clean (no errors)

## Rollback

```bash
# If deployment has issues:
# 1. Railway dashboard → Deployments
# 2. Click previous deployment
# 3. Click "Redeploy"
```

## Performance Targets

- **Health Check**: < 100ms
- **Demo Endpoints**: < 500ms (cached)
- **API Endpoints**: < 2s (live APIs)

## Production Considerations

- [ ] Add rate limiting
- [ ] Add authentication/API keys
- [ ] Enable HTTPS (automatic with Railway)
- [ ] Set up monitoring/alerts
- [ ] Configure backups
- [ ] Add Sentry for error tracking

---

**Deployed URL**: Will be provided after deployment
**Status**: Ready for deployment
