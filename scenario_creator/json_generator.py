


"""
Builds descriptor.json and model.json from parameter lists
"""
class JsonFiles(object):
    def __init__(self):
        pass

    def _generateDescriptor(self):
        """
        Generate descriptor.json

        for param in params:
            schema_properties += sample_property.format(param.title) + ',\n'
            form_parameters += sample_form.format(param.title, "Please enter a valid" + param.title)

        --> something like this... have to come up with solution for commas
            after json object

        https://stackoverflow.com/questions/23110383/how-to-dynamically-build-a-json-object-with-python
        """

        sample_property = """first_parameter": {
                                "title": {},
                                "type": "string"
                            }"""

        sample_form = """{
                        "key": {},
                        "type": "text",
                        "feedback": false,
                        "placeholder": "",
                        "validationMessage": {}
                        }"""

        schema_properties = ""
        form_parameters = ""



    def _generateModel(self):
        """
        Generate model.json

        for param in params:
            model_parameters += sample_parameter.format(param.title) + ',\n'

        -->same comma issue as above
        """
        # Eventually add some global param that can fill in the
        # description part
        sample_parameter = "{} : ''"
        model_parameters = ""
