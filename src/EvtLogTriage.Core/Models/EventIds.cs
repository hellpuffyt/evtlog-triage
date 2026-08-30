namespace EvtLogTriage.Core.Models;

/// <summary>Well-known Windows Security event IDs used by the detection rules.</summary>
public static class EventIds
{
    public const int SuccessfulLogon = 4624;
    public const int FailedLogon = 4625;
    public const int SpecialPrivilegesAssigned = 4672;
    public const int UserAccountCreated = 4720;
    public const int MemberAddedToSecurityGroup = 4732;
    public const int UserAccountDeleted = 4726;
    public const int AuditLogCleared = 1102;
    public const int ServiceInstalled = 7045;
    public const int ExplicitCredentialLogon = 4648;
}
