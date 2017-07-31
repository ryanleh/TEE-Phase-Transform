
class CollectionUtilsClass(object):
    def __init__(self):
        pass

    @staticmethod
    def NameValueArrayToDictionary(nv_array):
        tmphash = {}
        if nv_array:
            for nv in nv_array:
                name = nv.get('name')
                value = nv.get('value')
                if name and value:
                    tmphash[name] = value

        return tmphash
