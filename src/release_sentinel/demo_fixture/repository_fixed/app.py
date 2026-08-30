# Corrected demo fixture: cross-tenant access is denied.
def can_read(requester_tenant: str, resource_tenant: str) -> bool:
    return requester_tenant == resource_tenant
