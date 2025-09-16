/*
V0502 - CWE-502: Deserialization of Untrusted Data 
The application deserializes untrusted data without sufficiently
verifying that the resulting data will be valid, potentially leading 
to code execution or injection.
*/

//V0502 - Pickle Deserialization
FIND $F($A)
WHERE MATCH($F, "pickle\\.load|pickle\\.loads|cPickle\\.load|cPickle\\.loads")


// V0502 - YAML Deserialization
FIND $F($A)
WHERE MATCH($F, "yaml\\.load")


// V0502 - Marshall Deserialization
FIND $F($A)
WHERE MATCH($F, "marshal\\.load|marshal\\.loads")


// V0502 - Shelve Usage 
FIND $F($A)
WHERE MATCH($F, "shelve\\.open")

//V0502 - JSONPickle Usage 
FIND $F($A)
WHERE MATCH($F, "jsonpickle\\.decode")


