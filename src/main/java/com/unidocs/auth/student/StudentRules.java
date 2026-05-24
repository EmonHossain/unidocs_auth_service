package com.unidocs.auth.student;

import java.time.Instant;
import java.util.Set;

/** Domain rules shared by user operations and service reconciliation. */
public final class StudentRules {
    private StudentRules() { }
    public static final Set<String> ADMIN_OPERATIONS=Set.of("student.admission.review","course.catalog.read",
            "course.catalog.create","course.catalog.update","course.catalog.remove","semester.create",
            "student.report.review","student.report.evidence.submit");
    public static final Set<String> COLLABORATION=Set.of("file.share","file.share.view","file.share.edit",
            "folder.share","folder.share.view","folder.share.edit","content.access.update",
            "file.collaborative.edit","group.invitation.issue","group.invitation.accept","study.group.create");
    public static final Set<String> RECOVERY=Set.of("file.read","file.download","file.copy","folder.read",
            "folder.copy","workspace.read","group.read","quota.read","deletion.read","group.delete.cancel");
    public static boolean admitted(String state) {
        return "ACTIVE".equals(state)||"COLLABORATION_RESTRICTED".equals(state);
    }
    public static boolean permits(String state,String operation) {
        return admitted(state) && !("COLLABORATION_RESTRICTED".equals(state)&&COLLABORATION.contains(operation));
    }
    public static boolean catalogMutable(String offering,Instant startsAt,Instant now) {
        return !"FINALIZED".equals(offering)&&!"RETIRED".equals(offering)&&now.isBefore(startsAt);
    }
    public static boolean joinable(String offering,String readiness,Instant start,Instant end,Instant now) {
        return Set.of("OFFERED","FINALIZED").contains(offering)&&"READY".equals(readiness)
                && !now.isBefore(start)&&now.isBefore(end);
    }
    public static boolean groupAvailable(String status,Instant deadline,String operation,Instant now) {
        return "ACTIVE".equals(status)||RECOVERY.contains(operation)&&("PREPARING".equals(status)
                ||"CLOSING".equals(status)&&deadline!=null&&now.isBefore(deadline));
    }
    public static boolean validDecision(String action,String proofKind,boolean escalatedReport) {
        return switch(action) {
            case "RESTRICT","REVERSE" -> "POLICY_VIOLATION".equals(proofKind)&&escalatedReport;
            case "REMOVE_INTRUDER" -> "INTRUDER".equals(proofKind)&&escalatedReport;
            case "REMOVE_TERMINATED" -> "STUDENTSHIP_TERMINATION".equals(proofKind);
            default -> false;
        };
    }
}
