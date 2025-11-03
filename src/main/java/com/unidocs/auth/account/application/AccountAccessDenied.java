package com.unidocs.auth.account.application;
public final class AccountAccessDenied extends RuntimeException {
    public AccountAccessDenied() { super("Account operation is forbidden."); }
}
