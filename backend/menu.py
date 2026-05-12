"""
menu.py
Reads the menu from a public Google Sheet CSV and returns it structured
by category. Called on every /order page load so changes reflect immediately.

Sheet columns: id, name_en, name_gr, price, category, available
"""

import csv
import io
import os
import logging
import requests
from collections import defaultdict

logger = logging.getLogger(__name__)

CATEGORIES = {
    "espresso":  {"en": "☕ Espresso-Based", "gr": "☕ Εσπρεσσό",    "color": "cat-espresso"},
    "cold":      {"en": "🧊 Cold Coffee",    "gr": "🧊 Κρύος Καφές", "color": "cat-cold"},
    "noncoffee": {"en": "🍵 Non-Coffee",     "gr": "🍵 Χωρίς Καφέ", "color": "cat-noncoffee"},
    "drinks":    {"en": "🥤 Drinks",         "gr": "🥤 Ποτά",        "color": "cat-drinks"},
    "bar":       {"en": "🍺 Bar",            "gr": "🍺 Μπαρ",        "color": "cat-bar"},
    "snacks":    {"en": "🥐 Snacks",         "gr": "🥐 Σνακ",        "color": "cat-snacks"},
}


def fetch_menu() -> list[dict]:
    sheet_url = os.environ.get("MENU_SHEET_URL", "")
    if not sheet_url:
        logger.warning("MENU_SHEET_URL not set — menu will be empty")
        return []

    try:
        response = requests.get(
            sheet_url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
            allow_redirects=True
        )
        response.raise_for_status()
        raw = response.content.decode("utf-8-sig")

        # Log first line for debugging
        first_line = raw.split('\n')[0].strip()
        logger.info("Menu first line: %s", first_line[:150])

        # Detect delimiter
        delimiter = ';' if ';' in first_line else ','
        logger.info("Delimiter detected: %r", delimiter)

        reader = csv.DictReader(io.StringIO(raw), delimiter=delimiter)
        by_cat = defaultdict(list)
        count  = 0

        for row in reader:
            # Clean keys and values
            row = {k.strip().lstrip('\ufeff'): v.strip() for k, v in row.items() if k}

            item_id   = row.get("id", "").strip()
            name_en   = (row.get("name_en") or row.get("name") or "").strip()
            name_gr   = (row.get("name_gr") or "").strip()
            price_str = row.get("price", "0").strip().replace(",", ".")
            category  = row.get("category", "").strip().lower()
            available = row.get("available", "yes").strip().lower() in ("yes", "true", "1", "y")

            if not item_id or not name_en or not category:
                continue

            # Skip if this looks like a header row
            if item_id.lower() == 'id' or category.lower() == 'category':
                continue

            try:
                price = float(price_str)
            except ValueError:
                price = 0.0

            by_cat[category].append({
                "id":        item_id,
                "name_en":   name_en,
                "name_gr":   name_gr or name_en,
                "price":     price,
                "available": available,
            })
            count += 1

        logger.info("Parsed %d items, categories: %s", count, list(by_cat.keys()))

        # Build ordered category list
        menu = []
        for cat_id, cat_info in CATEGORIES.items():
            items = by_cat.get(cat_id, [])
            if items:
                menu.append({
                    "id":    cat_id,
                    "en":    cat_info["en"],
                    "gr":    cat_info["gr"],
                    "color": cat_info["color"],
                    "products": items,
                })

        # Unknown categories
        for cat_id, items in by_cat.items():
            if cat_id not in CATEGORIES and items:
                logger.warning("Unknown category: %s", cat_id)
                menu.append({
                    "id":    cat_id,
                    "en":    cat_id.capitalize(),
                    "gr":    cat_id.capitalize(),
                    "color": "cat-espresso",
                    "products": items,
                })

        logger.info("Menu ready: %d categories, %d items", len(menu), count)
        return menu

    except Exception as e:
        logger.error("Failed to fetch menu: %s", str(e), exc_info=True)
        return []