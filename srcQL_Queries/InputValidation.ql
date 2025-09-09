// catch direct calls to input(), eval(), exec(), compile()
FIND //src:call/src:name[
        .='input' or
        .='eval' or
        .='exec' or
        .='compile'
     ]
// catch sys.argv
FIND sys.argv

// catch os.environ
FIND os.environ
