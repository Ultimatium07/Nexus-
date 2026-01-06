"""
Nexus Media Telegram Bot with WebApp Integration
Features: AES encryption, WebApp buttons, rate limiting, honeypot detection
"""

import os
import json
import time
import hashlib
import secrets
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from base64 import b64encode, b64decode
from collections import defaultdict

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    filters,
    ContextTypes
)

# Cryptography imports
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ========== CONFIGURATION ==========
BOT_TOKEN = os.getenv("BOT_TOKEN", "7483264783:AAG6dTaO_sEdsZQCYO5pT5aNLPgmy8SrYFQ")
WEBAPP_URL = os.getenv("WEBAPP_URL", "https://ultimatium07.github.io/Nexus-/asadbekjon.html")
AES_KEY = os.getenv("AES_KEY", "nexus_secret_key_32bytes_long!!")  # 32 bytes for AES-256
TTL_SECONDS = 300  # 5 minutes

# Rate limiting
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 30

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ========== IN-MEMORY STORAGE (Replace with DB in production) ==========
user_data_store: Dict[int, Dict[str, Any]] = {}
rate_limit_store: Dict[int, list] = defaultdict(list)
banned_users: set = set()
honeypot_triggers: Dict[int, int] = defaultdict(int)


# ========== AES ENCRYPTION ==========
def encrypt_payload(data: dict) -> str:
    """Encrypt user data with AES-256-CBC and return base64 encoded string."""
    try:
        # Add timestamp and nonce for security
        data['timestamp'] = int(time.time())
        data['nonce'] = secrets.token_hex(8)
        
        json_data = json.dumps(data, separators=(',', ':'))
        
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Create cipher
        key = AES_KEY.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad and encrypt
        padded_data = pad(json_data.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        
        # Combine IV + encrypted data and encode
        combined = iv + encrypted
        return b64encode(combined).decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return ""


def decrypt_payload(encrypted_data: str) -> Optional[dict]:
    """Decrypt AES-256-CBC encrypted payload."""
    try:
        combined = b64decode(encrypted_data)
        
        # Extract IV and encrypted data
        iv = combined[:16]
        encrypted = combined[16:]
        
        # Create cipher
        key = AES_KEY.encode('utf-8')[:32].ljust(32, b'\0')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        data = json.loads(decrypted.decode('utf-8'))
        
        # Validate TTL
        if 'timestamp' in data:
            age = int(time.time()) - data['timestamp']
            if age > TTL_SECONDS:
                logger.warning(f"Payload expired: {age}s old")
                return None
        
        return data
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None


def get_webapp_url(user_id: int, tab: str = "profile") -> str:
    """Generate WebApp URL with encrypted user payload."""
    user_data = get_user_data(user_id)
    user_data['initial_tab'] = tab
    
    encrypted = encrypt_payload(user_data)
    if encrypted:
        return f"{WEBAPP_URL}?payload={encrypted}"
    return WEBAPP_URL


# ========== USER DATA MANAGEMENT ==========
def get_user_data(user_id: int) -> dict:
    """Get or create user data."""
    if user_id not in user_data_store:
        user_data_store[user_id] = {
            "user_id": user_id,
            "username": "",
            "xp": 0,
            "gold": 100,
            "level": 1,
            "streak": 0,
            "avatar": "🧑‍💻",
            "is_premium": False,
            "created_at": datetime.now().isoformat(),
            "xp_history": [0, 0, 0, 0, 0, 0, 0]
        }
    return user_data_store[user_id]


def update_user_data(user_id: int, updates: dict) -> dict:
    """Update user data with new values."""
    user_data = get_user_data(user_id)
    user_data.update(updates)
    user_data_store[user_id] = user_data
    return user_data


def add_xp(user_id: int, amount: int) -> dict:
    """Add XP to user and handle level ups."""
    user_data = get_user_data(user_id)
    user_data['xp'] += amount
    
    # Update XP history (last 7 days)
    user_data['xp_history'] = user_data['xp_history'][1:] + [user_data['xp']]
    
    # Level up logic (100 XP per level)
    new_level = (user_data['xp'] // 100) + 1
    if new_level > user_data['level']:
        user_data['level'] = new_level
        user_data['gold'] += 50 * (new_level - 1)  # Bonus gold for level up
    
    user_data_store[user_id] = user_data
    return user_data


# ========== RATE LIMITING ==========
def check_rate_limit(user_id: int) -> bool:
    """Check if user has exceeded rate limit."""
    current_time = time.time()
    
    # Clean old entries
    rate_limit_store[user_id] = [
        t for t in rate_limit_store[user_id] 
        if current_time - t < RATE_LIMIT_WINDOW
    ]
    
    if len(rate_limit_store[user_id]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    
    rate_limit_store[user_id].append(current_time)
    return True


def is_banned(user_id: int) -> bool:
    """Check if user is banned."""
    return user_id in banned_users


def ban_user(user_id: int, reason: str = ""):
    """Ban a user."""
    banned_users.add(user_id)
    logger.warning(f"User {user_id} banned. Reason: {reason}")


# ========== HONEYPOT HANDLING ==========
def handle_honeypot(user_id: int):
    """Handle honeypot trigger - ban after 3 triggers."""
    honeypot_triggers[user_id] += 1
    if honeypot_triggers[user_id] >= 3:
        ban_user(user_id, "honeypot_triggered_3_times")
        return True
    return False


# ========== WEBAPP DATA HANDLER ==========
async def handle_webapp_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle data received from WebApp."""
    user_id = update.effective_user.id
    
    if is_banned(user_id):
        await update.message.reply_text("⛔ Sizning hisobingiz bloklangan.")
        return
    
    if not check_rate_limit(user_id):
        await update.message.reply_text("⚠️ Juda ko'p so'rov. Biroz kuting.")
        return
    
    try:
        data = json.loads(update.effective_message.web_app_data.data)
        action = data.get('action', '')
        
        logger.info(f"WebApp data from {user_id}: {action}")
        
        # Handle different actions
        if action == 'ban_me':
            # Honeypot triggered
            reason = data.get('reason', 'unknown')
            if handle_honeypot(user_id):
                await update.message.reply_text("⛔ Xavfsizlik buzilishi aniqlandi.")
            return
        
        elif action == 'flashcard_answer':
            card_id = data.get('card_id')
            is_correct = data.get('correct', False)
            
            if is_correct:
                add_xp(user_id, 10)
                await update.message.reply_text("✅ To'g'ri javob! +10 XP")
            else:
                await update.message.reply_text("❌ Noto'g'ri. Qaytadan urinib ko'ring!")
        
        elif action == 'shop_purchase':
            item_id = data.get('item_id')
            price = data.get('price', 0)
            
            user_data = get_user_data(user_id)
            if user_data['gold'] >= price:
                user_data['gold'] -= price
                update_user_data(user_id, user_data)
                await update.message.reply_text(f"🛒 Xarid muvaffaqiyatli! -{price} 💰")
            else:
                await update.message.reply_text("❌ Yetarli oltin yo'q!")
        
        elif action == 'premium_purchase':
            plan = data.get('plan', 'monthly')
            # Here you would integrate with payment system
            await update.message.reply_text(
                f"💎 Premium {plan} rejasi tanlandi!\n"
                "To'lov tizimi tez orada qo'shiladi."
            )
        
        elif action == 'quiz_complete':
            score = data.get('score', 0)
            total = data.get('total', 0)
            xp_earned = score * 10
            add_xp(user_id, xp_earned)
            await update.message.reply_text(
                f"🎯 Quiz yakunlandi!\n"
                f"Natija: {score}/{total}\n"
                f"+{xp_earned} XP qo'shildi!"
            )
        
        elif action == 'start_ai_quiz':
            # Start AI Quiz - redirect to bot for quiz generation
            keyboard = [[
                InlineKeyboardButton(
                    "🤖 AI Quiz boshlash",
                    callback_data="ai_quiz_start"
                )
            ]]
            await update.message.reply_text(
                "🤖 *AI Quiz*\n\n"
                "AI tomonidan generatsiya qilingan savollar bilan bilimingizni sinang!\n\n"
                "📚 Mavzuni tanlang va boshlang:",
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode='Markdown'
            )
        
        else:
            logger.warning(f"Unknown action: {action}")
    
    except json.JSONDecodeError:
        logger.error("Invalid JSON from WebApp")
    except Exception as e:
        logger.error(f"WebApp data error: {e}")


# ========== BOT HANDLERS ==========
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    user = update.effective_user
    user_id = user.id
    
    if is_banned(user_id):
        await update.message.reply_text("⛔ Sizning hisobingiz bloklangan.")
        return
    
    # Initialize user data
    user_data = get_user_data(user_id)
    user_data['username'] = user.username or user.first_name
    update_user_data(user_id, user_data)
    
    keyboard = [
        [
            InlineKeyboardButton(
                "👤 Profil", 
                web_app=WebAppInfo(url=get_webapp_url(user_id, "profile"))
            ),
            InlineKeyboardButton(
                "📚 Ta'lim", 
                web_app=WebAppInfo(url=get_webapp_url(user_id, "edu"))
            )
        ],
        [
            InlineKeyboardButton(
                "🎮 Gamification", 
                web_app=WebAppInfo(url=get_webapp_url(user_id, "gamification"))
            ),
            InlineKeyboardButton(
                "💎 Premium", 
                web_app=WebAppInfo(url=get_webapp_url(user_id, "premium"))
            )
        ],
        [
            InlineKeyboardButton("🤖 AI Quiz", callback_data="ai_quiz"),
            InlineKeyboardButton("📊 Statistika", callback_data="stats")
        ]
    ]
    
    await update.message.reply_text(
        f"🌟 *Xush kelibsiz, {user.first_name}!*\n\n"
        "Nexus Media - AI bilan o'rganish platformasi.\n\n"
        "📱 *WebApp tugmalarini bosing:*",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )


async def profile_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /profile command."""
    user_id = update.effective_user.id
    
    if is_banned(user_id):
        await update.message.reply_text("⛔ Sizning hisobingiz bloklangan.")
        return
    
    keyboard = [[
        InlineKeyboardButton(
            "👤 Profilni ochish",
            web_app=WebAppInfo(url=get_webapp_url(user_id, "profile"))
        )
    ]]
    
    await update.message.reply_text(
        "👤 *Profil*\n\nProfilingizni ko'rish uchun tugmani bosing:",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )


async def edu_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /edu command."""
    user_id = update.effective_user.id
    
    if is_banned(user_id):
        await update.message.reply_text("⛔ Sizning hisobingiz bloklangan.")
        return
    
    keyboard = [[
        InlineKeyboardButton(
            "📚 Ta'limni ochish",
            web_app=WebAppInfo(url=get_webapp_url(user_id, "edu"))
        )
    ]]
    
    await update.message.reply_text(
        "📚 *Ta'lim*\n\nFlashcardlar bilan o'rganing:",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )


async def gamification_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /gamification command."""
    user_id = update.effective_user.id
    
    if is_banned(user_id):
        await update.message.reply_text("⛔ Sizning hisobingiz bloklangan.")
        return
    
    keyboard = [[
        InlineKeyboardButton(
            "🎮 Gamification",
            web_app=WebAppInfo(url=get_webapp_url(user_id, "gamification"))
        )
    ]]
    
    await update.message.reply_text(
        "🎮 *Gamification*\n\nLeaderboard va do'kon:",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )


async def premium_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /premium command."""
    user_id = update.effective_user.id
    
    if is_banned(user_id):
        await update.message.reply_text("⛔ Sizning hisobingiz bloklangan.")
        return
    
    keyboard = [[
        InlineKeyboardButton(
            "💎 Premium",
            web_app=WebAppInfo(url=get_webapp_url(user_id, "premium"))
        )
    ]]
    
    await update.message.reply_text(
        "💎 *Premium*\n\nMaxsus imkoniyatlarni oching:",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle callback queries."""
    query = update.callback_query
    user_id = query.from_user.id
    
    if is_banned(user_id):
        await query.answer("⛔ Hisobingiz bloklangan", show_alert=True)
        return
    
    await query.answer()
    
    if query.data == "ai_quiz":
        await query.message.reply_text(
            "🤖 *AI Quiz*\n\n"
            "Tez orada qo'shiladi!\n"
            "AI yordamida savollar generatsiya qilinadi.",
            parse_mode='Markdown'
        )
    
    elif query.data == "stats":
        user_data = get_user_data(user_id)
        await query.message.reply_text(
            f"📊 *Statistika*\n\n"
            f"👤 Level: {user_data['level']}\n"
            f"⭐ XP: {user_data['xp']}\n"
            f"💰 Oltin: {user_data['gold']}\n"
            f"🔥 Streak: {user_data['streak']} kun\n"
            f"💎 Premium: {'Ha' if user_data['is_premium'] else 'Yo\\'q'}",
            parse_mode='Markdown'
        )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command."""
    await update.message.reply_text(
        "📖 *Yordam*\n\n"
        "*Buyruqlar:*\n"
        "/start - Boshlash\n"
        "/profile - Profil\n"
        "/edu - Ta'lim\n"
        "/gamification - O'yinlashtirish\n"
        "/premium - Premium\n"
        "/help - Yordam\n\n"
        "*WebApp tugmalari:*\n"
        "• 👤 Profil - XP, level, statistika\n"
        "• 📚 Ta'lim - Flashcardlar\n"
        "• 🎮 Gamification - Leaderboard, do'kon\n"
        "• 💎 Premium - Maxsus imkoniyatlar",
        parse_mode='Markdown'
    )


# ========== MAIN ==========
def main():
    """Start the bot."""
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        logger.error("Please set BOT_TOKEN environment variable!")
        return
    
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("profile", profile_command))
    application.add_handler(CommandHandler("edu", edu_command))
    application.add_handler(CommandHandler("gamification", gamification_command))
    application.add_handler(CommandHandler("premium", premium_command))
    application.add_handler(CommandHandler("help", help_command))
    
    # Callback handler
    application.add_handler(CallbackQueryHandler(callback_handler))
    
    # WebApp data handler
    application.add_handler(MessageHandler(
        filters.StatusUpdate.WEB_APP_DATA,
        handle_webapp_data
    ))
    
    logger.info("Bot started!")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
