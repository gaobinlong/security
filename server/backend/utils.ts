
export interface RoleTenantPermission {
    tenant_patterns: string[];
    allowed_actions: string[];
}

export interface RoleDetail {
    tenant_permissions: RoleTenantPermission[];
}

export interface RoleMappingDetail {
    users: string[];
    backend_roles: string[];
}

export enum TenantPrincipalType {
    Users = 'users',
    BackendRoles = 'backend_roles',
}

export function tenantCanMatchPatterns(tenant: string, tenantPatterns: string[]) {
    if (!tenant || !tenantPatterns) {
        return false;
    }

    for (const tenantPattern of tenantPatterns) {
        if (tenantPattern === '*' || tenantPattern === tenant) {
            return true;
        }
        if (tenantPattern.startsWith('*') && tenant.endsWith(tenantPattern.substring(1, tenantPattern.length)) ||
            tenantPattern.endsWith('*') && tenant.startsWith(tenantPattern.substring(0, tenantPattern.length - 1))) {
            return true;
        }
    }
    return false;
}
