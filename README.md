# STIX Threat Analyzer

A comprehensive machine learning-powered platform for analyzing and visualizing STIX (Structured Threat Information Expression) data.

## 🚀 Overview

The STIX Threat Analyzer allows security analysts to upload STIX files and get real-time threat intelligence scores using a deterministic machine learning pipeline. It provides interactive graph visualizations to understand the relationships between different threat actors, indicators, and malware.

## ✨ Features

- **ML-Powered Analysis**: Uses a Random Forest classifier to determine threat levels (Low, Medium, High).
- **Interactive Visualization**: Dynamic 2D graph visualization of STIX objects and relationships.
- **Robust Parser**: Handles standard STIX 2.x formats and provides graceful degradation for non-STIX data.
- **Modern UI**: Built with React, Framer Motion, and Tailwind CSS for a premium user experience.
- **Containerized**: Full Docker support for both development and production.

## 🛠️ Tech Stack

- **Backend**: FastAPI, Python, Scikit-learn, STIX2 library.
- **Frontend**: React, Vite, Framer Motion, React-force-graph.
- **Data**: MongoDB & Neo4j (Optional/Supported).

## 🏃 Getting Started

### Prerequisites
- Python 3.9+
- Node.js 18+
- Docker (Optional)

### Running Locally

#### Backend
1. Navigate to the backend directory: `cd backend`
2. Create and activate a virtual environment.
3. Install dependencies: `pip install -r requirements.txt`
4. Start the server: `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`

#### Frontend
1. Navigate to the frontend directory: `cd frontend`
2. Install dependencies: `npm install`
3. Start the dev server: `npm run dev`

Access the application at [http://localhost:5173](http://localhost:5173).

## 🐳 Docker Support

Run the entire stack with a single command:
```bash
docker-compose up --build
```

## 📄 License

MIT
