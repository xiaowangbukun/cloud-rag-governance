# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS build

WORKDIR /src
COPY package.json package-lock.json* ./
RUN npm ci || npm install --no-audit --no-fund

COPY index.html vite.config.ts tsconfig.json ./
COPY src ./src
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /src/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 仅暴露静态资源目录，日志写入 stdout
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
