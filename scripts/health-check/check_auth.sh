#!/bin/bash
curl -f http://localhost:8080/health || echo "Auth service unhealthy"