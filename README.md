# DevSecOps AI Assistant

## Features
- SSH, Firewall, and Cowrie honeypot log analysis
- Anomaly detection (rules + Isolation Forest)
- Incident summarization and risk scoring
- Natural language queries (Gemini-powered intent parsing)
- Blocklist management (block/unblock IPs)
- Time series and forecasting
- Interactive dashboard (Streamlit)

## Requirements

- Python 3.8+
- The following Python packages (see `requirements.txt`):    

  ```
  streamlit
  pandas
  scikit-learn
  numpy
  google-generativeai
  ```

## Setup

1. Clone the repository.

2. Install dependencies:

   ```
   pip install -r requirements.txt
   ```

3. Set up your `.env` file with your Google Gemini API key:

   ```
   GOOGLE_API_KEY=your_api_key_here
   ```

4. Place your log files in the `data/` directory:

   - `sample_logs.csv` (SSH)
   - `firewall_logs.csv` (Firewall)
   - `cowrie_logs.csv` (Cowrie honeypot)

## Running

Start the Streamlit app:

```
streamlit run streamlit_app.py
```

## Usage

- Select log source and parameters in the sidebar.
- View dashboard, incidents, and chat tabs.
- Ask questions in natural language (e.g., "ban 10.0.3.107", "top 5 IPs with failed logins").
- Manage blocklist from the sidebar.

## File Structure

- `streamlit_app.py` — Main UI
- `detector.py` — Detection logic
- `forecast.py` — Forecasting
- `storage.py` — Blocklist and filtering
- `chat.py` — NL intent parsing
- `requirements.txt` — Dependencies
- `data/` — Log files
