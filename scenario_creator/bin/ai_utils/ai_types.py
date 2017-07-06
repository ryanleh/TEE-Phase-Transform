AI_SCENARIO_TYPE_NAME = {
  'AI_SCENARIO_INVALID' : 0,
  'AI_SCENARIO_ATTACK' : 1,
  'AI_SCENARIO_VALIDATION' : 2
}

AI_TRACE_TYPE = {
  'AI_TRACE_INVALID' : 0,
  'AI_TRACE_DEBUG'   : 1,
  'AI_TRACE_INFO'    : 2,
  'AI_TRACE_WARNING' : 3,
  'AI_TRACE_ERROR'   : 4,
  'AI_TRACE_REPORT'  : 5,
  'AI_TRACE_MITIGATION' : 6
}

#values are from loggging.LEVEL
AI_SIMPLE_TRACE_TYPE = {
  'invalid'     : (0  ,0),
  'debug'       : (10 ,1),
  'info'        : (20 ,2),
  'warning'     : (30 ,3),
  'error'       : (40 ,4),
  'report'      : (50 ,5),
  'mitigation'  : (60 ,6)
}

AI_OUTCOME_TYPE = {
  'OUTCOME_INVALID' : 0,
  'OUTCOME_PASSED'  : 1,
  'OUTCOME_FAILED'  : 2,
  'OUTCOME_ERRORED' : 3,
  'OUTCOME_DETECTED': 4
}

AI_HASHING_ALGORITHIM_TYPE = {
  'AI_HASHING_TYPE_NONE' : 0,
  'AI_HASHING_TYPE_MD5'  : 1,
  'AI_HASHING_TYPE_SHA1' : 2,
}
