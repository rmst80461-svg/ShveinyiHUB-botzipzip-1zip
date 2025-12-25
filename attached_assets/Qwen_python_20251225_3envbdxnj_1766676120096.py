from flask import Flask, render_template, jsonify, request, redirect, url_for, session, Response
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

# ----------------------------
# Настройка логирования и загрузка .env
# ----------------------------
# Путь к .env: на уровень выше текущего файла
env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    logging.warning(f".env file not found at {env_path}")

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Добавление корневой директории в sys.path (для импорта utils)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ----------------------------
# Импорт из utils.database (должен быть доступен!)
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
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Проверка обязательных настроек
if not BOT_TOKEN:
    logger.warning("BOT_TOKEN is not set. Telegram notifications will be disabled.")
if not ADMIN_PASSWORD:
    logger.warning("ADMIN_PASSWORD is not set. Defaulting to 'admin'.")
    ADMIN_PASSWORD = 'admin'
if not FLASK_SECRET_KEY:
    logger.warning("FLASK_SECRET_KEY not set. Generating temporary one.")
    FLASK_SECRET_KEY = secrets.token_hex(32)

# ----------------------------
# Инициализация Flask
# ----------------------------
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

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
м. Ховрино, ТЦ \"Бусиново\", 1 этаж

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
    """Отправить уведомление клиенту через Telegram API"""
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN not configured")
        return False

    try:
        # ✅ Исправлено: убран пробел после 'bot'
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": user_id,
            "text": message,
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=data, timeout=10)
        if response.status_code == 200:
            logger.info(f"Notification sent to user {user_id}")
            return True
        else:
            logger.error(f"Failed to send notification: {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error sending notification: {e}")
        return False

def get_service_name(service_type):
    """Получить русское название услуги"""
    return SERVICE_NAMES.get(service_type, service_type or 'Услуга')

def sanitize_input(text):
    """Sanitize user input to prevent XSS"""
    if text is None:
        return None
    return html.escape(str(text))

def check_auth(username, password):
    """Check if a username/password combination is valid"""
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

def requires_auth(f):
    """Decorator that requires session authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ----------------------------
# Роуты
# ----------------------------
@app.route('/health')
def health():
    """Health check эндпоинт"""
    stats = get_statistics()
    return jsonify({
        "status": "alive",
        "timestamp": datetime.now().isoformat(),
        "orders": stats.get('total_orders', 0),
        "users": stats.get('total_users', 0)
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if check_auth(username, password):
            session['logged_in'] = True
            session['username'] = username
            logger.info(f"User '{username}' logged in successfully")
            return redirect(url_for('index'))
        else:
            logger.warning(f"Failed login attempt for username: '{username}'")
            error = 'Неверный логин или пароль'
    return render_template('login.html', error=error)

@app.route('/change-password', methods=['GET', 'POST'])
@requires_auth
def change_password():
    """Change admin password"""
    error = None
    success = None
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not new_password:
            error = 'Пароль не может быть пустым'
        elif len(new_password) < 4:
            error = 'Пароль слишком короткий (мин. 4 символа)'
        elif new_password != confirm_password:
            error = 'Пароли не совпадают'
        else:
            # Обновляем пароль в памяти (для постоянного хранения нужен файл/БД)
            global ADMIN_PASSWORD
            ADMIN_PASSWORD = new_password
            os.environ['ADMIN_PASSWORD'] = new_password  # для текущего процесса
            success = 'Пароль успешно изменён!'
    return render_template('change_password.html', error=error, success=success)

@app.route('/logout')
def logout():
    """Logout"""
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"User '{username}' logged out")
    return redirect(url_for('login'))

@app.route('/')
@requires_auth
def index():
    """Главная страница админки"""
    stats = get_statistics()
    return render_template('index.html', stats=stats)

# ... остальные роуты остаются без изменений ...
# (orders, users, spam, reviews, api-роуты и т.д.)

@app.route('/orders')
@requires_auth
def orders():
    status = request.args.get('status', None)
    period = request.args.get('period', None)
    user_id_filter = request.args.get('user_id', None)
    date_from = request.args.get('date_from', None)
    date_to = request.args.get('date_to', None)
    month_filter = request.args.get('month', None)
    year_filter = request.args.get('year', None)

    all_orders = get_all_orders(limit=500)

    if user_id_filter:
        try:
            user_id_int = int(user_id_filter)
            all_orders = [o for o in all_orders if o.user_id == user_id_int]
        except ValueError:
            pass

    now = datetime.now()

    if date_from and date_to:
        try:
            start = datetime.strptime(date_from, '%Y-%m-%d')
            end = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            all_orders = [o for o in all_orders if o.created_at and start <= o.created_at <= end]
        except ValueError:
            pass
    elif period:
        if period == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            all_orders = [o for o in all_orders if o.created_at and o.created_at >= start_date]
        elif period == 'yesterday':
            start_date = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            all_orders = [o for o in all_orders if o.created_at and start_date <= o.created_at < end_date]
        elif period == 'week':
            start_date = now - timedelta(days=7)
            all_orders = [o for o in all_orders if o.created_at and o.created_at >= start_date]
        elif period == 'month':
            start_date = now - timedelta(days=30)
            all_orders = [o for o in all_orders if o.created_at and o.created_at >= start_date]

    if month_filter and year_filter:
        try:
            m = int(month_filter)
            y = int(year_filter)
            all_orders = [o for o in all_orders if o.created_at and o.created_at.month == m and o.created_at.year == y]
        except ValueError:
            pass
    elif year_filter:
        try:
            y = int(year_filter)
            all_orders = [o for o in all_orders if o.created_at and o.created_at.year == y]
        except ValueError:
            pass

    counts = {
        'all': len(all_orders),
        'new': len([o for o in all_orders if o.status == 'new']),
        'in_progress': len([o for o in all_orders if o.status == 'in_progress']),
        'completed': len([o for o in all_orders if o.status == 'completed']),
        'issued': len([o for o in all_orders if o.status == 'issued']),
        'cancelled': len([o for o in all_orders if o.status == 'cancelled']),
    }

    if status:
        orders_list = [o for o in all_orders if o.status == status]
    else:
        orders_list = all_orders

    orders_list = sorted(orders_list, key=lambda x: x.created_at or datetime.min, reverse=True)

    years_available = sorted(set(o.created_at.year for o in get_all_orders(limit=500) if o.created_at), reverse=True)
    if not years_available:
        years_available = [now.year]

    return render_template('orders.html',
                          orders=orders_list,
                          service_names=SERVICE_NAMES,
                          counts=counts,
                          current_status=status,
                          period=period,
                          date_from=date_from,
                          date_to=date_to,
                          month_filter=month_filter,
                          year_filter=year_filter,
                          years_available=years_available)

@app.route('/users')
@requires_auth
def users():
    users_list = get_all_users()
    all_orders = get_all_orders(limit=1000)

    order_counts = {}
    for order in all_orders:
        uid = order.user_id
        if uid:
            order_counts[uid] = order_counts.get(uid, 0) + 1

    return render_template('users.html', users=users_list, order_counts=order_counts)

@app.route('/spam')
@requires_auth
def spam():
    spam_list = get_spam_logs(limit=50)
    return render_template('spam.html', spam_logs=spam_list)

@app.route('/reviews')
@requires_auth
def reviews():
    filter_type = request.args.get('filter', 'all')
    if filter_type == 'approved':
        reviews_list = get_all_reviews(approved_only=True)
    else:
        reviews_list = get_all_reviews()
    stats = get_review_stats()
    return render_template('reviews.html', reviews=reviews_list, stats=stats, filter_type=filter_type)

@app.route('/api/reviews')
@requires_auth
def api_reviews():
    reviews_list = get_all_reviews()
    return jsonify([{
        'id': r.id,
        'order_id': r.order_id,
        'user_id': r.user_id,
        'rating': r.rating,
        'comment': sanitize_input(r.comment),
        'is_approved': r.is_approved,
        'rejected_reason': sanitize_input(r.rejected_reason),
        'created_at': r.created_at.isoformat() if r.created_at else None
    } for r in reviews_list])

@app.route('/api/review/<int:review_id>/moderate', methods=['POST'])
@requires_auth
def api_moderate_review(review_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400

    approve = bool(data.get('approve', True))
    reason = sanitize_input(data.get('reason'))

    if reason and len(reason) > 500:
        return jsonify({'error': 'Reason too long'}), 400

    success = moderate_review(review_id, approve, reason)

    if success:
        return jsonify({'success': True, 'review_id': review_id, 'approved': approve})
    else:
        return jsonify({'error': 'Review not found'}), 404

@app.route('/api/reviews/stats')
@requires_auth
def api_review_stats():
    stats = get_review_stats()
    return jsonify(stats)

@app.route('/api/stats')
@requires_auth
def api_stats():
    stats = get_statistics()
    return jsonify(stats)

@app.route('/api/orders')
@requires_auth
def api_orders():
    orders_list = get_all_orders(limit=50)
    return jsonify([{
        'id': o.id,
        'user_id': o.user_id,
        'service_type': sanitize_input(o.service_type),
        'client_name': sanitize_input(o.client_name),
        'client_phone': sanitize_input(o.client_phone),
        'status': o.status,
        'created_at': o.created_at.isoformat() if o.created_at else None
    } for o in orders_list])

@app.route('/api/order/<int:order_id>/status', methods=['POST'])
@requires_auth
def api_update_order_status(order_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400

    new_status = data.get('status')

    if new_status not in ['new', 'in_progress', 'completed', 'issued', 'cancelled']:
        return jsonify({'error': 'Invalid status'}), 400

    order = get_order(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    user_id = order.user_id

    success = update_order_status(order_id, new_status)

    if success:
        if new_status in STATUS_MESSAGES and user_id:
            message = STATUS_MESSAGES[new_status].format(order_id=order_id)
            notification_sent = send_telegram_notification(user_id, message)
            logger.info(f"Status update notification for order {order_id}: sent={notification_sent}")

        return jsonify({'success': True, 'order_id': order_id, 'status': new_status})
    else:
        return jsonify({'error': 'Failed to update status'}), 500

@app.route('/api/order/<int:order_id>/confirmation', methods=['POST'])
@requires_auth
def api_send_confirmation(order_id):
    return jsonify({'success': True, 'message': 'Confirmation disabled to avoid duplicates'})

@app.route('/api/users')
@requires_auth
def api_users():
    users_list = get_all_users()
    return jsonify([{
        'id': u.id,
        'user_id': u.user_id,
        'username': sanitize_input(u.username),
        'first_name': sanitize_input(u.first_name),
        'phone': sanitize_input(u.phone),
        'is_blocked': u.is_blocked,
        'created_at': u.created_at.isoformat() if u.created_at else None
    } for u in users_list])

@app.route('/api/orders/export-csv')
@requires_auth
def api_export_csv():
    status = request.args.get('status', None)
    period = request.args.get('period', None)
    date_from = request.args.get('date_from', None)
    date_to = request.args.get('date_to', None)
    month_filter = request.args.get('month', None)
    year_filter = request.args.get('year', None)

    all_orders = get_all_orders(limit=1000)
    now = datetime.now()

    if date_from and date_to:
        try:
            start = datetime.strptime(date_from, '%Y-%m-%d')
            end = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            all_orders = [o for o in all_orders if o.created_at and start <= o.created_at <= end]
        except ValueError:
            pass
    elif period:
        if period == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            all_orders = [o for o in all_orders if o.created_at and o.created_at >= start_date]
        elif period == 'yesterday':
            start_date = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            all_orders = [o for o in all_orders if o.created_at and start_date <= o.created_at < end_date]
        elif period == 'week':
            start_date = now - timedelta(days=7)
            all_orders = [o for o in all_orders if o.created_at and o.created_at >= start_date]
        elif period == 'month':
            start_date = now - timedelta(days=30)
            all_orders = [o for o in all_orders if o.created_at and o.created_at >= start_date]

    if month_filter and year_filter:
        try:
            m = int(month_filter)
            y = int(year_filter)
            all_orders = [o for o in all_orders if o.created_at and o.created_at.month == m and o.created_at.year == y]
        except ValueError:
            pass
    elif year_filter:
        try:
            y = int(year_filter)
            all_orders = [o for o in all_orders if o.created_at and o.created_at.year == y]
        except ValueError:
            pass

    if status:
        all_orders = [o for o in all_orders if o.status == status]

    STATUS_LABELS = {
        'new': 'Новый',
        'in_progress': 'В работе',
        'completed': 'Готов',
        'issued': 'Выдан',
        'cancelled': 'Отменён'
    }

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(['ID', 'Услуга', 'Клиент', 'Телефон', 'Статус', 'Дата создания'])

    for order in all_orders:
        writer.writerow([
            order.id,
            SERVICE_NAMES.get(order.service_type, order.service_type or ''),
            order.client_name or '',
            order.client_phone or '',
            STATUS_LABELS.get(order.status, order.status),
            order.created_at.strftime('%d.%m.%Y %H:%M') if order.created_at else ''
        ])

    output.seek(0)
    filename = f"orders_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        output.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/api/orders/bulk-delete', methods=['POST'])
@requires_auth
def api_bulk_delete_orders():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400

    order_ids = data.get('ids', [])

    if not order_ids or not isinstance(order_ids, list):
        return jsonify({'error': 'No order ids provided'}), 400

    try:
        order_ids = [int(oid) for oid in order_ids]
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid order ids'}), 400

    if len(order_ids) > 100:
        return jsonify({'error': 'Too many orders to delete at once (max 100)'}), 400

    valid_ids = [oid for oid in order_ids if 0 < oid < 2147483647]
    if not valid_ids:
        return jsonify({'error': 'No valid order ids'}), 400

    deleted_count = delete_orders_bulk(valid_ids)
    logger.info(f"Bulk deleted {deleted_count} orders: {valid_ids}")

    return jsonify({'success': True, 'deleted': deleted_count})

@app.route('/api/order/<int:order_id>', methods=['DELETE'])
@requires_auth
def api_delete_order(order_id):
    success = delete_order(order_id)
    if success:
        logger.info(f"Deleted order {order_id}")
        return jsonify({'success': True, 'order_id': order_id})
    else:
        return jsonify({'error': 'Order not found or could not be deleted'}), 404

# ----------------------------
# Запуск приложения
# ----------------------------
def run_webapp():
    """Запустить веб-приложение"""
    port = int(os.getenv('PORT', 5000))  # Для совместимости с облаками (Render, Heroku)
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    run_webapp()