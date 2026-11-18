"""Límite de solicitudes por clave (IP) y minuto para endpoints públicos sin sesión."""
from datetime import datetime


class Limiter:
    """ponytail: contador por proceso y ventana de 1 minuto. Con varios workers el tope efectivo se multiplica;
    pasar a Redis o al proxy (nginx limit_req) si hay abuso real."""

    def __init__(self, per_minute: int):
        self.per_minute, self.hits = per_minute, {}

    def allow(self, key: str, n: int, at: datetime) -> bool:
        window = int(at.timestamp() // 60)
        w, count = self.hits.get(key, (window, 0))
        count = count if w == window else 0
        if count + n > self.per_minute:
            return False
        if len(self.hits) > 50_000:  # memoria acotada
            self.hits.clear()
        self.hits[key] = (window, count + n)
        return True
