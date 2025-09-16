/*
V0269 - Improper Privilege Management
The software does not properly manage the privileges 
it has, allowing an attacker to gain more privileges 
than intended.
*/

// V0269 - Detect calls to os.setuid/os.setgid
FIND $F($A)
WHERE MATCH($F, "os\\.set(uid|gid)")


// V0269 - Detect use of os.seteuid / os.setegid
FIND $F($A)
WHERE MATCH($F, "os\\.sete(uid|gid)")


// V0269 - Detect subprocess calls with sudo or root execution
FIND $F($A)
WHERE MATCH($F, "subprocess\\.(call|run|Popen)")
  AND MATCH($A, "sudo")


// V0269 - Detect Privilege escalation wrappers (pty.spawn)
FIND $F($A)
WHERE MATCH($F, "pty\\.spawn")
