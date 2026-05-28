# Stage 1: Build React Application
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Serve with Production Nginx (Hardened Non-Root Environment)
FROM nginx:1.25-alpine

# Copy the compiled static folder from the builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# HARDENING STEPS: Reconfigure Nginx to run completely as non-root
# 1. Change the default listening port from 80 to 8080 (ports <1024 require root)
# 2. Grant the built-in 'nginx' user ownership over its cache, log, and runtime configuration paths
# 3. Create and set permissions for the PID file so Nginx can track its own process without root
RUN sed -i 's/listen       80;/listen       8080;/g' /etc/nginx/conf.d/default.conf \
    && chown -R nginx:nginx /var/cache/nginx /var/log/nginx /etc/nginx/conf.d /usr/share/nginx/html \
    && touch /var/run/nginx.pid \
    && chown nginx:nginx /var/run/nginx.pid

# Switch the container runtime context entirely away from root to the unprivileged 'nginx' user
USER nginx

# Expose the new unprivileged port
EXPOSE 8080

# Start Nginx in the foreground as normal
CMD ["nginx", "-g", "daemon off;"]