from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from django.db import models
from django.db.models.query import QuerySet
from django.utils import timezone
from django.utils.functional import cached_property

from sentry.backup.scopes import RelocationScope
from sentry.db.models import (
    BoundedBigIntegerField,
    BoundedPositiveIntegerField,
    FlexibleForeignKey,
    Model,
    region_silo_model,
    sane_repr,
)
from sentry.db.models.manager.base import BaseManager
from sentry.utils.groupreference import find_referenced_groups

if TYPE_CHECKING:
    from sentry.models.group import Group
    from sentry.models.release import Release


class CommitManager(BaseManager["Commit"]):
    def get_for_release(self, release: Release) -> QuerySet[Commit]:
        return (
            self.filter(releasecommit__release=release)
            .order_by("-releasecommit__order")
            .select_related("author")
        )


@region_silo_model
class Commit(Model):
    __relocation_scope__ = RelocationScope.Excluded

    organization_id = BoundedBigIntegerField(db_index=True)
    repository_id = BoundedPositiveIntegerField()
    key = models.CharField(max_length=64)
    date_added = models.DateTimeField(default=timezone.now)
    # all commit metadata must be optional, as it may not be available
    # when the initial commit object is referenced (and thus created)
    author = FlexibleForeignKey("sentry.CommitAuthor", null=True)
    message = models.TextField(null=True)

    objects: ClassVar[CommitManager] = CommitManager()

    class Meta:
        app_label = "sentry"
        db_table = "sentry_commit"
        indexes = (
            models.Index(fields=("repository_id", "date_added")),
            models.Index(fields=("author", "date_added")),
            models.Index(fields=("organization_id", "date_added")),
        )
        unique_together = (("repository_id", "key"),)

    __repr__ = sane_repr("organization_id", "repository_id", "key")

    @cached_property
    def title(self):
        if not self.message:
            return ""
        return self.message.splitlines()[0]

    @cached_property
    def short_id(self):
        if len(self.key) == 40:
            return self.key[:7]
        return self.key

    def find_referenced_groups(self) -> set[Group]:
        return find_referenced_groups(self.message, self.organization_id)
