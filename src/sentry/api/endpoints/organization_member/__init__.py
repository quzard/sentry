from __future__ import annotations

import logging
from collections.abc import Collection

from django.db import router, transaction
from rest_framework.request import Request

from sentry import roles
from sentry.auth.access import Access
from sentry.auth.superuser import is_active_superuser, superuser_has_permission
from sentry.locks import locks
from sentry.models.organization import Organization
from sentry.models.organizationmember import OrganizationMember
from sentry.models.organizationmemberteam import OrganizationMemberTeam
from sentry.models.team import Team
from sentry.roles.manager import Role, TeamRole
from sentry.utils.retries import TimedRetryPolicy

logger = logging.getLogger("sentry.org_roles")


def save_team_assignments(
    organization_member: OrganizationMember,
    teams: list[Team] | None,
    teams_with_roles: list[tuple[Team, str]] | None = None,
):
    # https://github.com/getsentry/sentry/pull/6054/files/8edbdb181cf898146eda76d46523a21d69ab0ec7#r145798271
    lock = locks.get(
        f"org:member:{organization_member.id}", duration=5, name="save_team_assignment"
    )
    with TimedRetryPolicy(10)(lock.acquire):
        if teams_with_roles:
            # Map will avoid O(n * n) search later
            team_role_map = {team.slug: role_id for team, role_id in teams_with_roles}
            target_teams = [team for team, _ in teams_with_roles]
        elif teams:
            team_role_map = {}
            target_teams = teams
        else:
            team_role_map = {}
            target_teams = []

        new_assignments = [(team, team_role_map.get(team.slug, None)) for team in target_teams]

        with transaction.atomic(router.db_for_write(OrganizationMemberTeam)):
            existing = OrganizationMemberTeam.objects.filter(organizationmember=organization_member)
            OrganizationMemberTeam.objects.bulk_delete(existing)
            OrganizationMemberTeam.objects.bulk_create(
                [
                    OrganizationMemberTeam(
                        organizationmember=organization_member, team=team, role=role
                    )
                    for team, role in new_assignments
                ]
            )


def can_set_team_role(request: Request, team: Team, new_role: TeamRole) -> bool:
    """
    User can set a team role:

    * If they are an active superuser (with the feature flag, they must be superuser write)
    * If they are an org owner/manager/admin
    * If they are a team admin on the team
    """
    if superuser_has_permission(request):
        return True

    access: Access = request.access
    if can_admin_team(access, team):
        return True

    org_role = access.get_organization_role()
    if org_role and org_role.can_manage_team_role(new_role):
        return True

    team_role = access.get_team_role(team)
    if team_role and team_role.can_manage(new_role):
        return True

    return False


def can_admin_team(access: Access, team: Team) -> bool:

    return access.has_team_membership(team) and (
        access.has_team_scope(team, "team:write")
        or access.has_scope("org:write")
        or access.has_scope("member:write")
    )


def get_allowed_org_roles(
    request: Request,
    organization: Organization,
    member: OrganizationMember | None = None,
    creating_org_invite: bool = False,
) -> Collection[Role]:
    """
    Get the set of org-level roles that the request is allowed to manage.

    In order to change another member's role, the returned set must include both
    the starting role and the new role. That is, the set contains the roles that
    the request is allowed to promote someone to and to demote someone from.

    If the request is to invite a new member, the member:admin scope is not required.
    """

    if is_active_superuser(request):
        return roles.get_all()

    # The member:admin scope is not required to invite a new member (when creating_org_invite is True).
    if not request.access.has_scope("member:admin") and not creating_org_invite:
        return ()

    if member is None:
        try:
            member = OrganizationMember.objects.get(
                user_id=request.user.id, organization=organization
            )
        except OrganizationMember.DoesNotExist:
            # This can happen if the request was authorized by an app integration
            # token whose proxy user does not have an OrganizationMember object.
            return ()

    return member.get_allowed_org_roles_to_invite()


from .details import OrganizationMemberDetailsEndpoint
from .index import OrganizationMemberIndexEndpoint
from .requests.invite.details import OrganizationInviteRequestDetailsEndpoint
from .requests.invite.index import OrganizationInviteRequestIndexEndpoint
from .requests.join import OrganizationJoinRequestEndpoint

__all__ = (
    "OrganizationInviteRequestDetailsEndpoint",
    "OrganizationInviteRequestIndexEndpoint",
    "OrganizationJoinRequestEndpoint",
    "OrganizationMemberDetailsEndpoint",
    "OrganizationMemberIndexEndpoint",
    "save_team_assignments",
    "can_set_team_role",
    "can_admin_team",
    "get_allowed_org_roles",
)
