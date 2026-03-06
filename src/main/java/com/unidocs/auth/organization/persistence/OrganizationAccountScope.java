package com.unidocs.auth.organization.persistence;

/** Current MySQL organization checks for account alias a and (for grants) grant alias sg. */
public final class OrganizationAccountScope {
    private OrganizationAccountScope() { }
    private static final String SCOPE = """
        (a.organization_id IS NULL OR EXISTS (
            SELECT 1 FROM organization scope_org
            JOIN organization_membership scope_member ON scope_member.organization_id=scope_org.id
            JOIN organization_auth_policy scope_policy ON scope_policy.organization_id=scope_org.id
            WHERE scope_org.id=a.organization_id AND scope_member.account_id=a.id
                AND scope_org.status='ACTIVE' AND scope_member.status='ACTIVE'
                AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r
                    WHERE r.organization_id=scope_org.id AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED'))
                AND scope_policy.enabled=true AND scope_policy.auth_method='PASSWORD'
                AND scope_policy.require_mfa=false AND scope_policy.email_domain IS NULL
                AND (%s IN ('LOGIN','PASSWORD') OR (%s='PIN' AND scope_policy.allow_pin_unlock=true))))
        """;
    public static final String PASSWORD = SCOPE.formatted("'PASSWORD'","'PASSWORD'");
    public static final String PIN = SCOPE.formatted("'PIN'","'PIN'");
    public static final String GRANT = SCOPE.formatted("sg.auth_method","sg.auth_method");
}
