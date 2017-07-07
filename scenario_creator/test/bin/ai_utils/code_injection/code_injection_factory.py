from ai_utils.code_injection.dll_injection_technique_1.appinit_dlls import AppInitDLLsAgentClass

class CodeInjectionAgentFactoryClass(object):
  def __init__(self, codeInjectionTechnique, dllPath='', rawCode=''):
    self.CodeInjectionTechnique = codeInjectionTechnique
    self.DLLPath = dllPath
    self.RawCode = rawCode

  def CreateAgent(self):
    if self.CodeInjectionTechnique == 'dll_injection_technique_1':
      return AppInitDLLsAgentClass(self.DLLPath)
    else:
      return None