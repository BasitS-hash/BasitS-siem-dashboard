# Installation

## Requirements

- Python 3.8 or higher
- pip

## Steps

### 1. Clone the repository

```bash
git clone https://github.com/basitsherazi/basit-siem-dashboard.git
cd basit-siem-dashboard
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure secrets

```bash
cp .env.example .env
# Edit .env — set SECRET_KEY and DATABASE_URI at minimum
```

### 5. Initialise the database

```bash
python db_utils.py init
```

### 6. (Optional) Generate sample data

```bash
python generate_sample_data.py
```

### 7. Start the services

```bash
# Terminal 1 — log ingestion
python log_ingestion.py &

# Terminal 2 — dashboard
python app.py
```

Open `http://localhost:8050` in your browser.

## Production deployment

Use Gunicorn behind a reverse proxy (nginx/Caddy):

```bash
gunicorn -w 4 -b 0.0.0.0:8050 "app:server"
```

Set `debug: false` in `config.yaml` or via the `APP_DEBUG` environment variable before deploying.
