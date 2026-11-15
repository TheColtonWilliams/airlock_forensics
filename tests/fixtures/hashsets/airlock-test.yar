// Tiny test rule for tests/unit/test_hashsets*.py and tests/functional/test_triage_hash.sh.
// Matches only a synthetic marker string; it detects nothing real.
rule Airlock_Test_Marker
{
    meta:
        description = "AIRLOCK test fixture marker (synthetic, harmless)"
    strings:
        $marker = "AIRLOCK-YARA-TEST-MARKER-7f3c"
    condition:
        $marker
}
