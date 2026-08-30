# Deliberately flawed demo fixture: cross-tenant access is incorrectly allowed.
def can_read(requester_tenant: str, resource_tenant: str) -> bool:
    return True
