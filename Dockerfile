FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN set -e; \
 for u in "https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-linux-64.zip" \
          "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"; do \
   curl -fsSL --retry 5 --retry-delay 2 -o /tmp/x.zip "$u" && break || echo "retry next url"; \
 done; \
 unzip -o /tmp/x.zip xray -d /usr/local/bin; chmod +x /usr/local/bin/xray; rm -f /tmp/x.zip; xray version
WORKDIR /app
RUN npm init -y >/dev/null && npm i qrcode-generator@1.4.4 --no-audit --no-fund
RUN npm i vazirmatn @fontsource-variable/inter @fontsource-variable/jetbrains-mono --no-audit --no-fund || echo 'fonts skipped'
COPY boot.js server.js index.html app.js sub.html style.css bg.svg ./
COPY assets ./assets
RUN date +%s > /app/BUILD_TS
ENV PORT=8080
EXPOSE 8080
CMD ["node","boot.js"]
