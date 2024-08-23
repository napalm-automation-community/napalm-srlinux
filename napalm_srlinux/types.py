from pydantic import BaseModel


class Interface(BaseModel):
    is_up: bool
    is_enabled: bool
    description: str | None
    last_flapped: float
    speed: float | None
    mtu: int | None
    mac_address: str | None
