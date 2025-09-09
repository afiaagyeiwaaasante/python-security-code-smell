// V0703 - CWE-703: Improper Exception Handling (bare except)
FIND //src:catch $E
WHERE NOT $E CONTAINS src:type
   OR ($E CONTAINS src:type/src:name[.='Exception' OR .='BaseException']
       AND NOT $E CONTAINS src:block/src:expr[src:name[.='raise']])
RETURN $E;

// V0703 - CWE-703: Improper Exception Handling (weak handling)
FIND //src:catch $E
WHERE $E CONTAINS src:type/src:name[.='Exception' OR .='BaseException']
   AND ALL($S IN $E/src:block/src:expr SATISFIES $S.get_name() MATCHES "pass|print" END)
RETURN $E;
