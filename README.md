# SecureLink - Malicious URL Detection System

SecureLink is a robust web application for detecting malicious URLs using machine learning, heuristic analysis, and real-time forensic checks.

## Features
- **Real-time URL Scanning**: Detects phishing, malware, and suspicious links.
- **Forensic Analysis**: Checks Domain Age, SSL Validity, Server Location, and more.
- **Machine Learning**: Uses a trained model for predictive analysis.
- **User Dashboard**: Track scan history and generate PDF reports.
- **Chrome Extension**: Scan URLs directly from your browser.
- **Admin Panel**: Manage users and view system statistics.

## Setup

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run Locally (Development)**:
    ```bash
    python app.py
    ```

3.  **Run Locally (Production)**:
    ```bash
    python deploy_local.py
    ```

## Deployment

See [DEPLOY.md](DEPLOY.md) for detailed instructions on deploying to the cloud (Render) and installing the Chrome Extension.

## Project Report
A comprehensive project report is available in `SecureLink_Final_Project_Report.pdf` (generated via `python generate_project_report.py`).
