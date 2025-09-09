// V0200 - CWE-200: Exposure of Sensitive Information (print)
FIND //src:call/src:name[
        .='print'
     ] CONTAINS src:argument[src:name OR src:literal]
WHERE $C CONTAINS src:argument/src:name MATCHES "password|secret|token|apikey|key"
   OR $C CONTAINS src:argument/src:literal MATCHES "password|secret|token|apikey|key"
RETURN $C;

// V0200 - CWE-200: Exposure of Sensitive Information (logging)
FIND //src:call/src:name[
        src:name[1]='logging' AND (src:name[2]='debug' OR src:name[2]='info' OR src:name[2]='warning')
     ] CONTAINS src:argument[src:name OR src:literal]
WHERE $C CONTAINS src:argument/src:name MATCHES "password|secret|token|apikey|key"
   OR $C CONTAINS src:argument/src:literal MATCHES "password|secret|token|apikey|key"
RETURN $C;

// V0200 - CWE-200: Exposure of Sensitive Information (HTTP responses)
FIND //src:call/src:name[
        .='jsonify' OR .='Response'
     ] CONTAINS src:argument[src:name OR src:literal]
WHERE $C CONTAINS src:argument/src:name MATCHES "password|secret|token|apikey|key"
   OR $C CONTAINS src:argument/src:literal MATCHES "password|secret|token|apikey|key"
RETURN $C;
