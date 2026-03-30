package com.unidocs.auth.registration.student;
public interface EvidenceStorage {
    void put(String key,StudentEvidence evidence);
    byte[] get(String key);
    void delete(String key);
}
