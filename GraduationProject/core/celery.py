"""
Celery application for the Malicious Document Detector.

Workers pull analysis jobs from the queue and process them
asynchronously (metadata extraction → YARA → VT → ML → report).
"""

import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")

app = Celery("maldoc_detector")
app.config_from_object("django.conf:settings", namespace="CELERY")

# Auto-discover tasks in each installed app's tasks.py
app.autodiscover_tasks()
