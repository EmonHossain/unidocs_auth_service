package com.unidocs.auth.authentication.browser;

public class BrowserRefreshDenied extends RuntimeException {
    public BrowserRefreshDenied() { super("Browser authentication request is forbidden."); }
}
