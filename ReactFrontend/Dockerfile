# Stage 1: Build React Application
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Serve with Production Nginx (Hardened Non-Root Environment)
FROM nginx:1.25-alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY --from=builder /app/welcome /usr/share/nginx/welcome

RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf

# HARDENING STEPS
RUN chown -R nginx:nginx /var/cache/nginx /var/log/nginx /etc/nginx/conf.d /usr/share/nginx/html /usr/share/nginx/welcome \
    && touch /var/run/nginx.pid \
    && chown nginx:nginx /var/run/nginx.pid

USER nginx

# Expose BOTH internal non-root ports
EXPOSE 8080 8081

CMD ["nginx", "-g", "daemon off;"]