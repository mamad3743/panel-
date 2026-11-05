FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN set -e; \
 case "$(uname -m)" in aarch64|arm64) F=Xray-linux-arm64-v8a.zip;; *) F=Xray-linux-64.zip;; esac; \
 for u in "https://github.com/XTLS/Xray-core/releases/download/v1.8.24/$F" \
          "https://github.com/XTLS/Xray-core/releases/latest/download/$F"; do \
   curl -fsSL --retry 5 --retry-delay 2 -o /tmp/x.zip "$u" && break || echo "retry next url"; \
 done; \
 unzip -o /tmp/x.zip xray -d /usr/local/bin; chmod +x /usr/local/bin/xray; rm -f /tmp/x.zip; xray version
WORKDIR /app
RUN npm init -y >/dev/null && npm i qrcode-generator@1.4.4 --no-audit --no-fund
RUN npm i vazirmatn @fontsource-variable/inter @fontsource-variable/jetbrains-mono --no-audit --no-fund || echo 'fonts skipped'
RUN npm i ssh2@1 --ignore-scripts --no-audit --no-fund || echo 'ssh2 skipped'
COPY *.js *.html *.css *.svg ./
COPY assets ./assets
RUN date +%s > /app/BUILD_TS
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node","boot.js"]
