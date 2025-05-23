# Generated by Django 5.2.1 on 2025-05-13 15:31

from sentry.new_migrations.migrations import CheckedMigration
from sentry.new_migrations.monkey.special import SafeRunSQL


class Migration(CheckedMigration):
    # This flag is used to mark that a migration shouldn't be automatically run in production.
    # This should only be used for operations where it's safe to run the migration after your
    # code has deployed. So this should not be used for most operations that alter the schema
    # of a table.
    # Here are some things that make sense to mark as post deployment:
    # - Large data migrations. Typically we want these to be run manually so that they can be
    #   monitored and not block the deploy for a long period of time while they run.
    # - Adding indexes to large tables. Since this can take a long time, we'd generally prefer to
    #   run this outside deployments so that we don't block them. Note that while adding an index
    #   is a schema change, it's completely safe to run the operation after the code has deployed.
    # Once deployed, run these manually via: https://develop.sentry.dev/database-migrations/#migration-deployment

    is_post_deployment = True

    dependencies = [
        ("hybridcloud", "0019_add_provider_webhook_payload"),
    ]

    operations = [
        SafeRunSQL(
            """\
            ALTER TABLE hybridcloud_apikeyreplica
            ALTER COLUMN scope_list TYPE text[] USING scope_list::text[];
            """,
            reverse_sql="",
            hints={"tables": ["hybridcloud_apikeyreplica"]},
        ),
    ]
