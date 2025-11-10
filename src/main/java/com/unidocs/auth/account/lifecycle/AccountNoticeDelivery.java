package com.unidocs.auth.account.lifecycle;

public interface AccountNoticeDelivery {
    boolean enabled();
    void deliver(String destination,LifecycleRepository.Notice notice);
}
