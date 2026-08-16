"""Configuration for the Huayitong appointment monitor."""
from . import settings
from .doctors import DOCTORS

if settings.PHONE_DOCTOR:
    DOCTORS = [settings.PHONE_DOCTOR]

__all__ = ["DOCTORS", "settings"]
