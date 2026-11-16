def load_records(payload: dict) -> list[dict]:
    rows = payload.get("instances", [])
    if not isinstance(rows, list):
        raise ValueError("instances must be a list")
    return [dict(row) for row in rows if isinstance(row, dict)]
