FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY --chown=node:node package.json server.js comparison.js ./
COPY --chown=node:node public ./public

USER node
EXPOSE 3000

CMD ["npm", "start"]
