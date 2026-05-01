# Multi-stage Dockerfile for Next.js Application
# Build: docker build -t hello-world-next-js .
# Run:   docker run -p 3000:3000 hello-world-next-js

FROM node:18-alpine AS builder

LABEL maintainer="security-research"
LABEL description="Next.js Hello World Application"

# Install dumb-init and required tools
RUN apk add --no-cache dumb-init

# Create app directory
WORKDIR /app

# Copy package files for better layer caching
COPY package*.json ./

# Install dependencies
RUN npm install --legacy-peer-deps && \
    npm cache clean --force

# Install CycloneDX globally for SBOM generation
RUN npm install -g @cyclonedx/cyclonedx-npm

# Generate SBOM in multiple formats
RUN cyclonedx-npm --ignore-npm-errors --output-file sbom-report.json --output-format JSON && \
    cyclonedx-npm --ignore-npm-errors --output-file sbom-report.xml --output-format XML

# Copy application source
COPY app ./app
COPY next.config.js ./

# Create .next directory with proper permissions
RUN mkdir -p .next && \
    chown -R node:node /app

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine

# Install dumb-init
RUN apk add --no-cache dumb-init

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm install --legacy-peer-deps --omit=dev && \
    npm cache clean --force

# Copy built application from builder
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/next.config.js ./
COPY --from=builder /app/app ./app

# Copy SBOM reports from builder
COPY --from=builder /app/sbom-report.json ./sbom-report.json
COPY --from=builder /app/sbom-report.xml ./sbom-report.xml

# Create metadata file with SBOM info
RUN echo "SBOM files generated at build time:" > /app/sbom-info.txt && \
    echo "  - /app/sbom-report.json (JSON format)" >> /app/sbom-info.txt && \
    echo "  - /app/sbom-report.xml (XML format)" >> /app/sbom-info.txt && \
    echo "" >> /app/sbom-info.txt && \
    echo "To extract SBOM from running container:" >> /app/sbom-info.txt && \
    echo "  docker cp <container_id>:/app/sbom-report.json ./" >> /app/sbom-info.txt

# Set proper ownership
RUN chown -R node:node /app

# Switch to non-root user
USER node

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Set environment
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the server
CMD ["npm", "start"]
