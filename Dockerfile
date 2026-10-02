FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build && npm prune --omit=dev

ENV NODE_ENV=production
ENV AGENTGUARD_STORAGE=postgres
ENV PORT=3100

EXPOSE 3100
USER node
CMD ["npm", "start"]
