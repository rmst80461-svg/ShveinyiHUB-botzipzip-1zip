import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv('BOT_TOKEN', 'your_token_here')
GIGACHAT_CREDENTIALS = os.getenv('GIGACHAT_CREDENTIALS', '')

# Parse ADMIN_IDS from environment variable (comma-separated string)
env_admin_ids = os.getenv('ADMIN_IDS', '')
if env_admin_ids:
    try:
        ADMIN_IDS = [int(x.strip()) for x in env_admin_ids.split(',')]
    except ValueError:
        ADMIN_IDS = [123456789]
else:
    ADMIN_IDS = [123456789, 8290911386]

DB_PATH = 'data/workshop.db'
