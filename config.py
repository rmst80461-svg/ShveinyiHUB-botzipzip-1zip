import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv('BOT_TOKEN', 'your_token_here')
GIGACHAT_CREDENTIALS = os.getenv('GIGACHAT_CREDENTIALS', '')
ADMIN_IDS = [123456789]
DB_PATH = 'data/workshop.db'
