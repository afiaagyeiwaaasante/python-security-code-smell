/*
V0434 - CWE-434: Unrestricted File Upload/Download (dangerous file types)
The software allows the uploading of files with dangerous types that can be 
automatically processed within the environment. This can lead to remote 
code execution, malware delivery, or data exfiltration.
*/

//V0434 - Detect file upload from request.files saved directly
FIND $S
WHERE MATCH($S, "(?i)request\\.files\\")

//V0434 - Detect file save without validation
FIND $F($A)
WHERE MATCH($F, "(?i)(save|store|upload)")
  AND MATCH($A, "(file|request\\.files)")

//V0434 - Detect /upload/ + style concatenation
FIND $S
WHERE MATCH($S, "/uploads/\\s*\\+\\s*")

//V0434 - Detect os.path.join(...)
FIND $S
WHERE MATCH($S, "os\\.path\\.join\\([^)]*(?:request|input|argv|environ)[^)]*\\)")

//V0434 - Detect Unrestricted file download 
FIND $F($ARG)
WHERE MATCH($F, "\\bopen\\b")
  AND MATCH($ARG, "(?i)(request|input|argv|environ)")

//V0434 - Detect lack of file extension checks
FIND $S
WHERE MATCH($S, "(?i)(filename|file\\.name)")
  AND NOT MATCH($S, "(?i)(endswith|splitext|allowed_extensions)")
