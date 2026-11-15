// Uses an external variable, as Neo23x0 signature-base rules do; compiles only when the
// build step defines the externals (empty). Never matches: the name is never passed.
rule Airlock_Test_External
{
    condition:
        filename == "airlock-never-set.exe"
}
