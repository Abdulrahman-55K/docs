"""
Ensure the Celery app is loaded when Django starts,
so that @shared_task decorators in app tasks.py files
are registered properly.
"""

from .celery import app as celery_app

__all__ = ["celery_app"]
