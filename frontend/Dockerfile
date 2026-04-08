FROM node:18-alpine

WORKDIR /app

COPY package.json .
# We don't have package-lock since we manually scaffolded, just npm install
RUN npm install

COPY . .

# Expose vite port
EXPOSE 5173

# Run dev server
CMD ["npm", "run", "dev"]
