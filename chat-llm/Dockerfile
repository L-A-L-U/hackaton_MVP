FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY package.json /app/package.json
# Si tienes package-lock.json estable, descomenta:
# COPY package-lock.json /app/package-lock.json
# RUN npm ci --omit=dev
RUN npm install --omit=dev

COPY server.js /app/server.js

EXPOSE 8787
CMD ["node", "server.js"]
