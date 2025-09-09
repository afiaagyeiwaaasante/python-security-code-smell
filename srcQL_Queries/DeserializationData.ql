// V0502 - CWE-502: Deserialization of Untrusted Data (pickle)
FIND //src:call/src:name[
        src:name[1]='pickle' AND 
        (src:name[2]='load' OR src:name[2]='loads')
     ] CONTAINS src:argument[src:name OR src:expr]
RETURN $C;

// V0502 - CWE-502: Deserialization of Untrusted Data (cPickle)
FIND //src:call/src:name[
        src:name[1]='cPickle' AND 
        (src:name[2]='load' OR src:name[2]='loads')
     ] CONTAINS src:argument[src:name OR src:expr]
RETURN $C;

// V0502 - CWE-502: Deserialization of Untrusted Data (yaml)
FIND //src:call/src:name[
        src:name[1]='yaml' AND src:name[2]='load'
     ] CONTAINS src:argument[src:name OR src:expr]
WHERE NOT $C CONTAINS src:call/src:name[.='safe_load']
RETURN $C;

// V0502 - CWE-502: Deserialization of Untrusted Data (marshal)
FIND //src:call/src:name[
        src:name[1]='marshal' AND 
        (src:name[2]='load' OR src:name[2]='loads')
     ] CONTAINS src:argument[src:name OR src:expr]
RETURN $C;
