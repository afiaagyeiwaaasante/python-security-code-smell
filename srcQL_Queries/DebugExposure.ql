// V0215 - CWE-215: Debug Info Exposure (DEBUG=True)
FIND src:assign $A;
WHERE $A CONTAINS src:name MATCHES "DEBUG"
  AND $A CONTAINS src:literal MATCHES "True"
RETURN $A;

// V0215 - CWE-215: Debug Info Exposure (verbose logging)
FIND //src:call/src:name[
        src:name[1]='logging' AND src:name[2]='debug'
     ] CONTAINS src:argument
RETURN $C;

// V0215 - CWE-215: Debug Info Exposure (stack traces or sensitive prints)
FIND //src:call/src:name[.='print' OR .='pprint'] CONTAINS src:argument/src:name
WHERE src:argument/src:name MATCHES "traceback|exception|error"
RETURN $C;
