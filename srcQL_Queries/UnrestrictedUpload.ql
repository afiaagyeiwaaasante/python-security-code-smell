// V0434 - CWE-434: Unrestricted File Upload/Download (dangerous file types)
FIND //src:call $C;
WHERE 
    // File operation calls
    $C.get_target().get_name() MATCHES "open|save|write|urllib.request.urlretrieve|requests.get|wget.download"
    // Input comes from untrusted source
    AND $C CONTAINS src:attribute[src:name='files'] OR $C CONTAINS src:argument[src:name='url']
    // File extension is dangerous
    AND $C CONTAINS src:literal[
        . ENDSWITH ".iso" OR
        . ENDSWITH ".tar" OR
        . ENDSWITH ".tar.gz" OR
        . ENDSWITH ".dmg" OR
        . ENDSWITH ".deb" OR
        . ENDSWITH ".bin" OR
        . ENDSWITH ".rpm" OR
        . ENDSWITH ".zip"
    ]
    // No integrity check present in sibling statements
    AND NOT $C FOLLOWED BY src:call/src:name[
        . CONTAINS "hashlib" OR
        . CONTAINS "gpg" OR
        . CONTAINS "sha1sum" OR
        . CONTAINS "sha256sum"
    ]
