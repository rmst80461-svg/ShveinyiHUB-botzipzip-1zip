from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ChatAction
from utils.gigachat_api import get_ai_response
from utils.anti_spam import anti_spam
from utils.database import add_user, is_user_blocked
from keyboards import get_main_menu, get_ai_response_keyboard
from handlers.admin import is_user_admin
import logging

logger = logging.getLogger(__name__)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработка текстовых сообщений"""
    if not update.message or not update.message.text:
        return
    
    user = update.effective_user
    user_id = user.id
    text = update.message.text
    
    if context.user_data.get('broadcast_mode') and is_user_admin(user_id):
        from handlers.admin import broadcast_send
        await broadcast_send(update, context)
        return
    
    add_user(
        user_id=user_id,
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name
    )
    
    if is_user_blocked(user_id):
        logger.warning(f"Blocked user {user_id} tried to send message")
        return
    
    is_spam, spam_reason = anti_spam.is_spam(user_id, text)
    if is_spam:
        logger.warning(f"Spam from {user_id}: {spam_reason}")
        await update.message.reply_text(
            f"⚠️ {spam_reason}\n\nПодождите немного перед следующим сообщением.",
            reply_markup=get_main_menu()
        )
        return
    
    logger.info(f"Сообщение от {user_id}: {text[:50]}")
    
    try:
        await context.bot.send_chat_action(
            chat_id=update.effective_chat.id, 
            action=ChatAction.TYPING
        )
        
        response, needs_human = await get_ai_response(text, user_id)
        
        keyboard = get_ai_response_keyboard(show_contact=needs_human)
        
        await update.message.reply_text(
            f"💬 {response}",
            reply_markup=keyboard
        )
    except Exception as e:
        logger.error(f"Ошибка при обработке сообщения: {e}")
        await update.message.reply_text(
            "Извините, произошла ошибка. Попробуйте позже или позвоните нам: +7 (968) 396-91-52",
            reply_markup=get_main_menu()
        )
