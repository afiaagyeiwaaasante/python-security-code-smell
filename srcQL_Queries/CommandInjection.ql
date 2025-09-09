// V0078 - CWE-78: OS Command Injection (os.system)
FIND //src:call/src:name[
        src:name[1]='os' and
        src:name[2]='system'
     ]

// V0078 - CWE-78: OS Command Injection (os.popen)
FIND //src:call/src:name[
        src:name[1]='os' and
        src:name[2]='popen'
     ]

// V0078 - CWE-78: OS Command Injection (subprocess.call)
FIND //src:call/src:name[
        src:name[1]='subprocess' and
        src:name[2]='call'
     ]

// V0078 - CWE-78: OS Command Injection (subprocess.run)
FIND //src:call/src:name[
        src:name[1]='subprocess' and
        src:name[2]='run'
     ]

// V0078 - CWE-78: OS Command Injection (subprocess.Popen)
FIND //src:call/src:name[
        src:name[1]='subprocess' and
        src:name[2]='Popen'
     ]

// V0078 - CWE-78: OS Command Injection (subprocess with shell=True)
FIND //src:call/src:name[
        src:name[1]='subprocess' and
        (src:name[2]='call' or src:name[2]='run' or src:name[2]='Popen')
     ] CONTAINS src:argument[src:name='shell' and src:literal='True']
