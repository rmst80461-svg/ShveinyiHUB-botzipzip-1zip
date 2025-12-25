#!/usr/bin/env python3
"""
Скрипт управления ботом.
"""

import asyncio
import sys
from utils.database import Database


async def show_stats():
    """Показать статистику."""
    db = Database()
    await db.init()
    stats = await db.get_statistics()

    print("\n📊 СТАТИСТИКА БОТА\n")
    print(f"Всего пользователей: {stats.get('total_users', 0)}")
    print(f"Всего заказов: {stats.get('total_orders', 0)}")
    print(f"Заблокировано: {stats.get('blocked_users', 0)}")

    db.close()


async def list_orders():
    """Показать последние заказы."""
    db = Database()
    await db.init()
    orders = await db.get_recent_orders(limit=10)

    print("\n📋 ПОСЛЕДНИЕ ЗАКАЗЫ\n")
    for order in orders:
        print(
            f"ID: {order['order_id']} | Услуга: {order['service_type']} | Статус: {order['status']}"
        )

    db.close()


async def main():
    """Главная функция."""
    if len(sys.argv) < 2:
        print("Использование: python manage.py <команда>")
        print("\nДоступные команды:")
        print("  stats  - Показать статистику")
        print("  orders - Показать заказы")
        return

    command = sys.argv[1]

    if command == "stats":
        await show_stats()
    elif command == "orders":
        await list_orders()
    else:
        print(f"Неизвестная команда: {command}")


if __name__ == "__main__":
    asyncio.run(main())
