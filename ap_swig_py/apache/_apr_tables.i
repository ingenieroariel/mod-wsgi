/* vim: set sw=4 expandtab : */

%extend apr_table_t {

    apr_table_entry_t* __element(int i) {
        return &((apr_table_entry_t*)apr_table_elts(self)->elts)[i];
    }

    %pythoncode %{

    def __contains__(self, key):
        return apr_table_get(self, key) != None

    def __delitem__(self, key):
        if not self.has_key(key):
            raise KeyError(key)
        apr_table_unset(key)

    def __getitem__(self, key):
        values = self.getlist(key)
        if not values:
            raise KeyError(key)
        if len(values) == 1:
            return values[0]
        return values

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return apr_table_elts(self).nelts

    def __repr__(self):
        values = {}
        for i in range(len(self)):
            key = self.__element(i).key
            if not values.has_key(key):
                values[key] = [self.__element(i).val]
            else:
                values[key].append(self.__element(i).val)
        return repr(values)

    def __setitem__(self, key, value):
        assert(key is not None)
        assert(value is not None)
        apr_table_set(self, key, value)

    def add(self, key, value):
        assert(key is not None)
        assert(value is not None)
        apr_table_add(self, key, value)

    def get(self, key, default=''):
        values = self.getlist(key)
        if not values:
            return default
        if len(values) == 1:
            return values[0]
        return values

    def getfirst(self, key, default=''):
        value = apr_table_get(self, key)
        if not value:
            return default
        return value

    def getlist(self, key):
        values = []
        for i in range(len(self)):
            if self.__element(i).key == key:
                values.append(self.__element(i).val)
        return values

    def has_key(self, key):
        return apr_table_get(self, key) != None

    def items(self):
        values = []
        for i in range(len(self)):
            values.append((self.__element(i).key, self.__element(i).val))
        return values

    def keys(self):
        values = {}
        for i in range(len(self)):
            values[self.__element(i).key] = None
        return values.keys()

    %}
};
