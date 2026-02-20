# SecureLink Deployment Guide

This guide explains how to deploy SecureLink locally (Windows/Mac/Linux) and to the cloud (Render/Heroku).

## 1. Local Deployment (Production Mode)

To run the application in a production-ready mode on your local machine:

1.  **Install Requirements** (if not already done):
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Deployment Script**:
    ```bash
    python deploy_local.py
    ```
    Or manually:
    ```bash
    python run_production.py
    ```

3.  Access the application at: `http://localhost:8080`

---

## 2. Cloud Deployment (Render.com - Recommended Free Tier)

SecureLink is ready for deployment on Render.com.

1.  **Push your code to GitHub**.
2.  **Sign up/Log in to Render.com**.
3.  Click **New +** -> **Web Service**.
4.  Connect your GitHub repository.
5.  **Settings**:
    -   **Name**: `securelink-app` (or similar)
    -   **Runtime**: Python 3
    -   **Build Command**: `pip install -r requirements.txt`
    -   **Start Command**: `gunicorn app:app` (This is already in the `Procfile`, so Render might auto-detect it)
6.  Click **Create Web Service**.
7.  Once deployed, copy your new URL (e.g., `https://securelink-app.onrender.com`).

---

## 3. Chrome Extension Usage

The Chrome Extension currently points to `http://localhost:5000` (Development) or `http://127.0.0.1:5000`.

### If running locally (Development):
1.  Open Chrome.
2.  Go to `chrome://extensions`.
3.  Enable **Developer Mode** (top right).
4.  Click **Load unpacked**.
5.  Select the `chrome_extension` folder in this project.
6.  Pin the extension and use it on any tab.

### If running locally (Production Port 8080):
1.  Open `chrome_extension/popup.js`.
2.  Change line 6:
    ```javascript
    const scanUrl = `http://127.0.0.1:8080/scan?url=${encodeURIComponent(tab.url)}`;
    ```
3.  Reload the extension in `chrome://extensions`.

### If deployed to Cloud (e.g., Render):
1.  Open `chrome_extension/popup.js`.
2.  Change line 6 to your cloud URL:
    ```javascript
    const scanUrl = `https://your-app-name.onrender.com/scan?url=${encodeURIComponent(tab.url)}`;
    ```
3.  Reload the extension in `chrome://extensions`.
