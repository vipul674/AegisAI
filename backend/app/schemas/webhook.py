"""
Pydantic schemas for WebhookConfig resource.
Copyright (C) 2024 Sarthak Doshi (github.com/SdSarthak)
SPDX-License-Identifier: AGPL-3.0-only
"""

import ipaddress
import socket
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, HttpUrl, field_validator


def _is_private_ip(hostname: str) -> bool:
    """Check if a hostname resolves to a private/reserved IP address."""
    try:
        addr = ipaddress.ip_address(hostname)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        for family, _, _, _, sockaddr in results:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return True
    except (socket.gaierror, OSError):
        pass

    return False


class WebhookCreate(BaseModel):
    url: HttpUrl
    secret: Optional[str] = None
    events: list[str] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def validate_webhook_url(cls, v: HttpUrl) -> HttpUrl:
        parsed = urlparse(str(v))
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only http and https schemes are allowed")
        hostname = parsed.hostname or ""
        if _is_private_ip(hostname):
            raise ValueError("Webhook URL must not point to private or internal network addresses")
        return v


class WebhookResponse(BaseModel):
    id: int
    url: str
    is_active: bool
    events: list[str]
    created_at: datetime

    class Config:
        from_attributes = True