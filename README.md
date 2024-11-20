# Threat Hunting Tool

This is a threat hunting tool that uses a Flask backend and React frontend to analyze system logs, detect indicators of compromise (IoCs), identify brute-force attacks, and fetch threat intelligence data. The tool allows users to interact with various threat-hunting functions through a web interface.

## Features

- Load system logs for analysis.
- Detect known Indicators of Compromise (IoCs).
- Identify brute-force attacks in log data.
- Fetch real-time threat intelligence information for IP addresses.
- Run osquery commands to query system information.
- Easy-to-use React frontend for interaction with backend APIs.

## Tech Stack

- **Frontend**: React.js
- **Backend**: Flask (Python)
- **Database**: In-memory data structures for simple log and threat data processing
- **Libraries**:
  - Flask for backend API
  - Axios for HTTP requests in React
  - Yara for detecting IoCs
  - Pandas and Numpy for data analysis
  - Requests for external API calls
  - Flask-RESTful for API routing

## Prerequisites

Before running the application, ensure you have the following installed on your machine:

- Python (version 3.x)
- Node.js (version 12.x or higher)
- npm (Node Package Manager)

## Installation Guide

### Step 1: Clone the Repository

First, clone this repository to your local machine:

```bash
git clone https://github.com/yourusername/threat_hunting_app.git
cd threat_hunting_app
Step 2: Set Up the Backend (Flask)
Navigate to the backend directory:

bash
Copy code
cd backend
Create a virtual environment:

bash
Copy code
python -m venv venv
Activate the virtual environment:

On Windows (PowerShell):

bash
Copy code
.\venv\Scripts\Activate.ps1
On Linux/Mac:

bash
Copy code
source venv/bin/activate
Install the required Python libraries:

bash
Copy code
pip install -r requirements.txt
Start the Flask backend:

bash
Copy code
flask run
This will start the backend API on http://localhost:5000.

Step 3: Set Up the Frontend (React)
Navigate to the frontend directory:

bash
Copy code
cd ../frontend
Install the necessary frontend dependencies:

bash
Copy code
npm install
Start the React development server:

bash
Copy code
npm start
This will open the React app in your browser at http://localhost:3000.

Usage
Once the application is running, you can interact with the tool through the frontend:

Click on the buttons to:
Load logs
Detect Indicators of Compromise (IoC)
Detect brute force attacks
Fetch threat intelligence data
Run osquery commands
The results will be displayed in the browser's console.

