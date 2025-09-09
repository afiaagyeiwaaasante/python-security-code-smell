// V0269 - CWE-269: Improper Privilege Management (UID/GID changes)
FIND //src:call/src:name[
        src:name[1]='os' AND
        (src:name[2]='setuid' OR src:name[2]='seteuid' OR src:name[2]='setgid' OR src:name[2]='setegid')
     ]

// V0269 - CWE-269: Improper Privilege Management (file ownership changes)
FIND //src:call/src:name[
        (src:name[1]='os' AND src:name[2]='chown') OR
        (src:name[1]='shutil' AND src:name[2]='chown')
     ]

// V0269 - CWE-269: Improper Privilege Management (sudo invocation)
FIND //src:call/src:name[
        src:name[1]='os' OR src:name[1]='subprocess'
     ] CONTAINS src:argument[src:literal[contains(.,"sudo")]]

// V0269 - CWE-269: Improper Privilege Management (root UID/GID)
FIND //src:call/src:name[
        src:name[1]='os' OR src:name[1]='subprocess' OR src:name[1]='shutil'
     ] CONTAINS src:argument[src:literal='0']
