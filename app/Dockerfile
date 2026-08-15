FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ocrmypdf \
       tesseract-ocr-deu \
       tesseract-ocr-eng \
       tesseract-ocr-nld \
       tesseract-ocr-swe \
       poppler-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --chown=node:node . .

USER node

EXPOSE 3000

CMD ["npm", "start"]
