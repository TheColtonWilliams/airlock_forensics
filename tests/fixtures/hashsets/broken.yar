// Deliberately does not compile (unknown module): the build step must skip it and list it.
import "airlock_no_such_module"
rule Airlock_Test_Broken { condition: true }
