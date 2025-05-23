# Generated by Django 3.2.20 on 2023-09-26 02:24

from django.db import migrations

import sentry.db.models.fields.array
from sentry.new_migrations.migrations import CheckedMigration
from sentry.new_migrations.monkey.special import SafeRunSQL


class Migration(CheckedMigration):
    # This flag is used to mark that a migration shouldn't be automatically run in production. For
    # the most part, this should only be used for operations where it's safe to run the migration
    # after your code has deployed. So this should not be used for most operations that alter the
    # schema of a table.
    # Here are some things that make sense to mark as post deployment:
    # - Large data migrations. Typically we want these to be run manually by ops so that they can
    #   be monitored and not block the deploy for a long period of time while they run.
    # - Adding indexes to large tables. Since this can take a long time, we'd generally prefer to
    #   have ops run this and not block the deploy. Note that while adding an index is a schema
    #   change, it's completely safe to run the operation after the code has deployed.
    is_post_deployment = False

    dependencies = [
        ("sentry", "0569_dashboard_widgets_indicator"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                SafeRunSQL(
                    """
                    ALTER TABLE "sentry_repository" ADD COLUMN "languages" TEXT[] NULL;
                    """,
                    reverse_sql="""
                    ALTER TABLE "sentry_repository" DROP COLUMN "languages";
                    """,
                    hints={"tables": ["sentry_repository"]},
                ),
            ],
            state_operations=[
                migrations.AddField(
                    model_name="repository",
                    name="languages",
                    field=sentry.db.models.fields.array.ArrayField(null=True),
                ),
            ],
        )
    ]
