// V0094 - CWE-94: Improper Control of Code Generation (Code Injection)
FIND //src:call $C;
WHERE $C.get_target().get_name() MATCHES "eval|exec|compile|pickle.loads|yaml.load"
  // Check if the argument is NOT a string literal (untrusted or dynamic input)
  AND $C CONTAINS src:argument[src:name OR src:expr]
  AND NOT $C CONTAINS src:argument/src:literal[@type='string']
RETURN $C;
