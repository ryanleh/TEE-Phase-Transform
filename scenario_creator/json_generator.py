
import json

"""
Builds descriptor.json and model.json from parameter lists
"""
class JsonFiles(object):
    def __init__(self, req_params, opt_params):
        self.params = req_params + opt_params

    def generateDescriptorSchema(self):
        """
        Generate descriptor.json

        TODO: Fix this multiline crap

        >>> JsonFiles(['req1', 'req2'],['opt1']).generateDescriptorSchema()
        '{"opt1": {"type": "string", "title": "opt1"}, "req1": {"type": "string", "title": "req1"}, "req2": {"type": "string", "title": "req2"}}'

        """

        schema_properties = {}

        for param in self.params:
            schema_properties[param] = {"title": param, "type": "string"}


        # TODO: add indent
        return json.dumps(schema_properties)


    def generateDescriptorForm(self):
        """
        form: return list of json dumps of dictionaries

        >>> JsonFiles(['req1', 'req2'],['opt1']).generateDescriptorForm()
        ['{"placeholder": "", "type": "text", "feedback": false, "key": "req1", "validationMessage": ""}', '{"placeholder": "", "type": "text", "feedback": false, "key": "req2", "validationMessage": ""}', '{"placeholder": "", "type": "text", "feedback": false, "key": "opt1", "validationMessage": ""}']
        """

        form_parameters = []

        for param in self.params:
            form_parameters.append(json.dumps({"key": param, "type": "text", "feedback": False, "placeholder": "",
                                                "validationMessage": ""}))


        # TODO: add indent
        return form_parameters


    def generateModel(self):
        """
        Generate model.json

        >>> JsonFiles(['req1', 'req2'],['opt1']).generateModel()
        '{"opt1": "", "req1": "", "req2": ""}'

        """
        # Eventually add some global param that can fill in the
        # description part
        model_parameters = {}

        for param in self.params:
            model_parameters[param] = ''

        # TODO: add indent
        return json.dumps(model_parameters)