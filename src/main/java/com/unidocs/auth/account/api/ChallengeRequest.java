package com.unidocs.auth.account.api;
import jakarta.validation.constraints.NotNull;
import com.unidocs.auth.account.domain.AccountChallenge.*;
public record ChallengeRequest(@NotNull Purpose purpose, @NotNull Method method) { }
