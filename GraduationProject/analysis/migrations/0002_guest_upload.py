from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Make uploaded_by nullable so guest uploads (no user) are allowed
        migrations.AlterField(
            model_name="file",
            name="uploaded_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="files",
                to=settings.AUTH_USER_MODEL,
                help_text="Authenticated user who uploaded. Null for guest uploads.",
            ),
        ),
        # Add guest_token to identify unauthenticated uploaders
        migrations.AddField(
            model_name="file",
            name="guest_token",
            field=models.CharField(
                blank=True,
                null=True,
                max_length=64,
                db_index=True,
                help_text="Browser-generated UUID for guest (unauthenticated) uploaders.",
            ),
        ),
    ]

    