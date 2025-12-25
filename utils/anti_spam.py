import time
import logging
from collections import defaultdict
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

BLACKLIST_WORDS = [
    'куплю', 'продам', 'купить', 'продать', 'реклама', 'заработок',
    'казино', 'ставки', 'криптовалют', 'биткоин', 'инвестиц',
    'кредит', 'займ', 'микрозайм', 'forex', 'трейдинг',
    'бесплатно деньги', 'выигрыш', 'лотерея', 'розыгрыш призов',
    'подписывайтесь', 'переходите по ссылке', 'жми на ссылку',
    'секс', 'порно', 'интим', 'эскорт'
]

WHITELIST_WORDS = [
    'ремонт', 'подшить', 'ушить', 'молния', 'пуговиц', 'заплатк',
    'штопк', 'шитье', 'пошив', 'одежд', 'брюки', 'платье', 'юбка',
    'куртк', 'пальто', 'костюм', 'рубашк', 'джинсы', 'сколько стоит',
    'цена', 'адрес', 'телефон', 'график', 'работ', 'срок', 'заказ',
    'услуг', 'ателье', 'мастерск', 'трикотаж', 'кожа', 'мех'
]

RATE_LIMIT = 5
RATE_WINDOW = 60
MUTE_DURATION = 300


class AntiSpamSystem:
    def __init__(self, max_messages_per_minute: int = RATE_LIMIT):
        self.max_messages = max_messages_per_minute
        self.user_messages: Dict[int, list] = defaultdict(list)
        self.muted_users: Dict[int, float] = {}
    
    def check_blacklist(self, text: str) -> Tuple[bool, str]:
        """Check if message contains blacklisted words"""
        text_lower = text.lower()
        
        for word in BLACKLIST_WORDS:
            if word in text_lower:
                return True, f"Черный список: '{word}'"
        
        return False, ""
    
    def check_whitelist(self, text: str) -> bool:
        """Check if message contains whitelisted words"""
        text_lower = text.lower()
        
        for word in WHITELIST_WORDS:
            if word in text_lower:
                return True
        
        return False
    
    def is_muted(self, user_id: int) -> Tuple[bool, int]:
        """Check if user is muted"""
        if user_id in self.muted_users:
            mute_end = self.muted_users[user_id]
            current_time = time.time()
            
            if current_time < mute_end:
                remaining = int(mute_end - current_time)
                return True, remaining
            else:
                del self.muted_users[user_id]
        
        return False, 0
    
    def mute_user(self, user_id: int, duration: int = MUTE_DURATION):
        """Mute user for specified duration"""
        self.muted_users[user_id] = time.time() + duration
        logger.warning(f"User {user_id} muted for {duration} seconds")
    
    def unmute_user(self, user_id: int):
        """Unmute user"""
        if user_id in self.muted_users:
            del self.muted_users[user_id]
    
    def is_spam(self, user_id: int, text: str = "") -> Tuple[bool, str]:
        """Check if user is spamming"""
        is_muted, remaining = self.is_muted(user_id)
        if is_muted:
            return True, f"Вы временно заблокированы. Осталось {remaining} сек."
        
        if text and self.check_whitelist(text):
            return False, ""
        
        if text:
            is_blacklisted, reason = self.check_blacklist(text)
            if is_blacklisted:
                self._log_spam_to_db(user_id, text, reason)
                self.mute_user(user_id)
                return True, "Сообщение содержит запрещённый контент."
        
        now = time.time()
        one_minute_ago = now - RATE_WINDOW
        
        self.user_messages[user_id] = [
            timestamp for timestamp in self.user_messages[user_id]
            if timestamp > one_minute_ago
        ]
        
        if len(self.user_messages[user_id]) >= self.max_messages:
            self.mute_user(user_id)
            self._log_spam_to_db(user_id, text, "Превышен лимит сообщений")
            return True, "Слишком много сообщений. Подождите немного."
        
        self.user_messages[user_id].append(now)
        return False, ""
    
    def _log_spam_to_db(self, user_id: int, text: str, reason: str):
        """Log spam attempt to database"""
        try:
            from .database import log_spam
            log_spam(user_id, text, reason)
            logger.warning(f"Spam from {user_id}: {reason}")
        except Exception as e:
            logger.error(f"Failed to log spam: {e}")
    
    def get_wait_time(self, user_id: int) -> int:
        """Get time user needs to wait before next message"""
        if not self.user_messages[user_id]:
            return 0
        
        oldest = self.user_messages[user_id][0]
        wait = int(60 - (time.time() - oldest)) + 1
        return max(0, wait)
    
    def reset_user(self, user_id: int):
        """Reset user's rate limit counter"""
        if user_id in self.user_messages:
            del self.user_messages[user_id]
        if user_id in self.muted_users:
            del self.muted_users[user_id]


anti_spam = AntiSpamSystem(max_messages_per_minute=RATE_LIMIT)
