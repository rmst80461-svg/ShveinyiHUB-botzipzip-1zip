from flask import Flask, render_template, jsonify, request, redirect, url_for, session, Response, make_response
from functools import wraps
import sys
import os
import secrets
import html
import logging
import requests
from dotenv import load_dotenv
import io
import csv
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect

# ----------------------------
# Настройка логирования и загрузка .env
# ----------------------------
env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    # also try local .env
    local_env = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(local_env):
        load_dotenv(local_env)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ----------------------------
# Импорт из utils.database
# ----------------------------
try:
    from utils.database import (
        get_all_orders, get_all_users, get_spam_logs,
        get_statistics, update_order_status, get_orders_by_status,
        get_all_reviews, get_review_stats, moderate_review, get_average_rating,
        get_order, delete_order, delete_orders_bulk
    )
except ImportError as e:
    logger.critical(f"Failed to import database module: {e}")
    sys.exit(1)

# ----------------------------
# Конфигурация
# ----------------------------
BOT_TOKEN = os.getenv('BOT_TOKEN')
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY') or secrets.token_hex(32)
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')
ADMIN_PASSWORD_FILE = os.path.join(os.path.dirname(__file__), '.admin_password.hash')

def load_admin_password():
    global ADMIN_PASSWORD
    if os.path.exists(ADMIN_PASSWORD_FILE):
        with open(ADMIN_PASSWORD_FILE, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return ADMIN_PASSWORD

# ----------------------------
# Инициализация Flask
# ----------------------------
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
csrf = CSRFProtect(app)

# Session cookie security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

logger.info(f"ADMIN_USERNAME loaded: '{ADMIN_USERNAME}'")
logger.info("Application initialized.")

# ----------------------------
# Константы
# ----------------------------
STATUS_MESSAGES = {
    'in_progress': '🧵 Отличные новости! Ваш заказ #{order_id} уже в работе!\n\nНаши мастера с любовью трудятся над вашим изделием. Совсем скоро всё будет готово! ✨',
    'issued': '📤 Ваш заказ #{order_id} выдан!\n\nСпасибо, что выбрали нашу мастерскую. Будем рады видеть вас снова! 🪡',
    'completed': '''🎉 Ваш заказ #{order_id} выполнен!

Спасибо, что доверили нам свою вещь! Мы очень старались и надеемся, что результат вас порадует.

📍 <b>Забрать можно по адресу:</b>
м. Ховрино, ТЦ "Бусиново", 1 этаж

⏰ <b>Часы работы:</b>
Пн-Чт: 10:00-19:50
Пт: 10:00-19:00
Сб: 10:00-17:00
Вс: выходной

📞 +7 (968) 396-91-52

---

🙏 <b>Будем признательны за ваш отзыв!</b>

Поделитесь своими честными впечатлениями о нашей работе — это поможет нам стать лучше и подскажет другим клиентам.

👉 <a href="https://yandex.ru/maps/org/shveyny_hub/1233246900/reviews/?ll=37.488846%2C55.881644&z=13">Оставить отзыв на Яндекс.Картах</a>

Ждём вас! 🪡''',
    'cancelled': '😔 К сожалению, ваш заказ #{order_id} был отменён.\n\nЕсли у вас остались вопросы или вы хотите оформить новый заказ — мы всегда рады помочь!\n\n📞 +7 (968) 396-91-52'
}

SERVICE_NAMES = {
    "jacket": "🧥 Ремонт пиджака",
    "leather": "🎒 Изделия из кожи",
    "curtains": "🪟 Пошив штор",
    "coat": "🧥 Ремонт куртки",
    "fur": "🐾 Шубы и дублёнки",
    "outerwear": "🧥 Плащ/пальто",
    "pants": "👖 Брюки/джинсы",
    "dress": "👗 Юбки/платья"
}

# ----------------------------
# Вспомогательные функции
# ----------------------------
def send_telegram_notification(user_id: int, message: str) -> bool:
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN not configured")
        return False
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = {"chat_id": user_id, "text": message, "parse_mode": "HTML"}
        response = requests.post(url, json=data, timeout=10)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Error sending notification: {e}")
        return False

def check_auth(username, password):
    current_admin_password = load_admin_password()
    # Support both plain text (from env) and hashed (from file) for simplicity in this migration
    if username != ADMIN_USERNAME:
        return False
    if os.path.exists(ADMIN_PASSWORD_FILE):
        return check_password_hash(current_admin_password, password)
    return password == current_admin_password

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if request.path.startswith('/api/') or request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ----------------------------
# Роуты
# ----------------------------
@app.route('/health')
def health():
    stats = get_statistics()
    return jsonify({
        "status": "alive",
        "timestamp": datetime.now().isoformat(),
        "orders": stats.get('total_orders', 0),
        "users": stats.get('total_users', 0)
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if check_auth(username, password):
            session.clear()
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            error = 'Неверный логин или пароль'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@requires_auth
def index():
    stats = get_statistics()
    return render_template('index.html', stats=stats)

@app.route('/webapp')
def webapp_form():
    """Эндпоинт для Telegram Web App формы заказа"""
    return render_template('webapp.html')

@app.route('/orders')
@requires_auth
def orders():
    status = request.args.get('status')
    period = request.args.get('period')
    all_orders = get_all_orders(limit=500)
    
    # Filter logic (simplified for brevity, matching original app.py style)
    if status:
        all_orders = [o for o in all_orders if o.status == status]
        
    return render_template('orders.html', orders=all_orders, service_names=SERVICE_NAMES)

@app.route('/api/order/<int:order_id>/status', methods=['POST'])
@requires_auth
@csrf.exempt
def api_update_order_status(order_id):
    data = request.get_json()
    new_status = data.get('status')
    if new_status not in ['new', 'in_progress', 'completed', 'issued', 'cancelled']:
        return jsonify({'error': 'Invalid status'}), 400
        
    order = get_order(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404
        
    if update_order_status(order_id, new_status):
        if new_status in STATUS_MESSAGES and order.user_id:
            msg = STATUS_MESSAGES[new_status].format(order_id=order_id)
            send_telegram_notification(order.user_id, msg)
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to update'}), 500

@app.errorhandler(404)
def not_found(e):
    return "<h1>404 Not Found</h1>", 404

@app.errorhandler(500)
def server_error(e):
    return "<h1>500 Internal Server Error</h1>", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
