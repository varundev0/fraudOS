"""Singleton InvestigationEngine — shared across the API and webhook routers."""

from .engine import InvestigationEngine

engine = InvestigationEngine()
