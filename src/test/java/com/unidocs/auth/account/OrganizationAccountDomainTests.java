package com.unidocs.auth.account;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.unidocs.auth.account.domain.*;
import com.unidocs.auth.account.domain.UserAccount;
import com.unidocs.auth.authentication.domain.LoginIdentity;

import static org.assertj.core.api.Assertions.*;

class OrganizationAccountDomainTests {
    @Test void accountScopeMustMatchTypeAndLinkMustMatchHuman() {
        UUID user=UUID.randomUUID(); UUID org=UUID.randomUUID(); Instant now=Instant.now();
        assertThatThrownBy(()->new UserAccount(UUID.randomUUID(),user,null,UserAccount.Type.COMPANY,"Company",now)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->new UserAccount(UUID.randomUUID(),user,org,UserAccount.Type.PERSONAL,"Personal",now)).isInstanceOf(IllegalArgumentException.class);
        UserAccount account=new UserAccount(UUID.randomUUID(),user,org,UserAccount.Type.UNIVERSITY,"University",now);
        assertThat(account.organizationId()).isEqualTo(org);
        assertThatThrownBy(()->new AccountGroupMember(account,UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),now)).isInstanceOf(IllegalArgumentException.class);
        assertThat(new AccountGroupMember(account,UUID.randomUUID(),user,UUID.randomUUID(),now)).isNotNull();
    }
    @Test void organizationLoginIdentifierMustBeItsAccountUuid() {
        UUID account=UUID.randomUUID();
        assertThatThrownBy(()->new LoginIdentity(UUID.randomUUID(),account,LoginIdentity.Type.ACCOUNT_ID,"other-id","encoded-hash",Instant.now()))
            .isInstanceOf(IllegalArgumentException.class);
        assertThat(new LoginIdentity(UUID.randomUUID(),account,LoginIdentity.Type.ACCOUNT_ID,account.toString(),"encoded-hash",Instant.now()).identifier()).isEqualTo(account.toString());
    }
}
