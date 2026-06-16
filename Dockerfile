# Use an official Node.js runtime as a parent image
FROM node:20-alpine

# Tini for proper signal handling / zombie reaping; iputils for a full-featured
# ping (BusyBox ping also works, but iputils is more consistent across hosts).
RUN apk add --no-cache tini iputils

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install production dependencies reproducibly from the lockfile
RUN npm ci --omit=dev

# Bundle app source
COPY . .

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3010

# Make the port available outside the container
EXPOSE 3010

# Lightweight container healthcheck hitting the unauthenticated liveness probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3010/healthz >/dev/null 2>&1 || exit 1

# Run under tini so SIGTERM reaches Node for graceful shutdown.
ENTRYPOINT ["/sbin/tini", "--"]

# Define the command to run your app (entry point is src/server.js)
CMD [ "node", "src/server.js" ]
