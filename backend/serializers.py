"""
serializers.py
View-model shaping for order JSON.

The identical ~14-line "build order dict" block appeared THREE times in app.py
(admin_dashboard, waiter_orders_api, api_admin_orders). It now lives here once,
producing byte-identical output to the original.
"""


def _iso_time(created_at) -> str:
    if created_at and hasattr(created_at, "isoformat"):
        return created_at.isoformat()
    if isinstance(created_at, str):
        return created_at
    return ""


def order_to_view(o: dict) -> dict:
    """Map a get_all_orders() row to the JSON shape the dashboards consume."""
    return {
        "id":          str(o["id"]),
        "short_id":    str(o["id"])[:8].upper(),
        "table_id":    o["table_id"],
        "order_items": o["order_items"],
        "status":      o["status"],
        "total":       float(o["total"]),
        "payment":     o.get("payment", "cash"),
        "source":      o.get("source", "customer"),
        "waiter_name": o.get("waiter_name") or "",
        "iso_time":    _iso_time(o.get("created_at")),
    }


def orders_to_view(raw_orders: list) -> list:
    return [order_to_view(o) for o in raw_orders]