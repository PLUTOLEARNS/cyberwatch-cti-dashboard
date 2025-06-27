# CyberWatch CTI Dashboard

A real-time Cyber Threat Intelligence (CTI) dashboard that aggregates and visualizes threat data from multiple free sources including AlienVault OTX and ThreatFox.

## Features

- **Real-time Threat Intelligence**: Live data from AlienVault OTX and ThreatFox APIs
- **Interactive Dashboard**: Visual analytics for threat metrics, IOC timeline, and malware families
- **Threat Lookup**: Check IP addresses, domains, URLs, and file hashes against multiple sources
- **Geographic Distribution**: Visual representation of threat origins by country
- **Malware Family Tracking**: Monitor trending malware families and categories
- **IOC Timeline**: Track indicators of compromise over time with detailed breakdowns

## Tech Stack

- **Backend**: Flask (Python 3.9+)
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: HTML/CSS/JavaScript with Chart.js and Bootstrap 5
- **APIs**: AlienVault OTX, ThreatFox (abuse.ch)
- **Deployment**: Docker support included

## Setup Instructions

### Prerequisites

- Python 3.9+
- AlienVault OTX API key (free registration at otx.alienvault.com)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cyberwatch-cti-dashboard.git
cd cyberwatch-cti-dashboard
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up your AlienVault OTX API key:
```bash
# On Windows
set ALIENVAULT_API_KEY=your-otx-api-key
# On macOS/Linux
export ALIENVAULT_API_KEY=your-otx-api-key
```

### Running the Application

1. Initialize the database and start the application:
```bash
python setup.py  # Creates database and sample data
python app.py    # Starts the Flask server
```

2. Access the dashboard at http://localhost:5000

### Docker Deployment

1. Build the Docker image:
```bash
docker build -t cyberwatch-cti .
```

2. Run the container:
```bash
docker run -p 5000:5000 -e ALIENVAULT_API_KEY=your-api-key cyberwatch-cti
```

3. Access the dashboard at http://localhost:5000

## Project Structure

```
cyberwatch-cti-dashboard/
├── app.py                     # Main Flask application
├── config.py                  # Configuration and API keys
├── setup.py                   # Database initialization
├── models/                    # Database models
│   ├── database.py           # Database setup
│   └── threat_intel.py       # Threat data models
├── services/                  # API service integrations
│   ├── api_clients/          # API client implementations
│   │   ├── alienvault_otx.py # AlienVault OTX integration
│   │   ├── threatfox.py      # ThreatFox integration
│   │   └── base_client.py    # Base API client
│   ├── data_processor.py     # Data processing and analytics
│   ├── threat_feeds.py       # Threat feed aggregation
│   └── threat_reports.py     # Report generation
├── static/                   # Static assets
│   ├── css/style.css        # Custom styling
│   └── js/                  # JavaScript files
├── templates/               # HTML templates
├── requirements.txt         # Python dependencies
└── Dockerfile              # Docker configuration
```

## API Sources

The dashboard integrates with the following **free** threat intelligence APIs:

- **AlienVault OTX**: Community-driven threat intelligence platform
- **ThreatFox (abuse.ch)**: Malware indicators of compromise database

## Features Demo

- **Dashboard**: Real-time threat metrics with interactive charts
- **Feeds**: Live threat intelligence feeds from multiple sources
- **Lookup**: IOC verification tool for IPs, domains, URLs, and hashes
- **Reports**: Automated threat intelligence reporting

## License

MIT License - Feel free to use and modify for your projects.

Your Name - your.email@example.com
