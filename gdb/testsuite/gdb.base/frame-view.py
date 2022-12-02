class Printer1:
    def to_string(self):
        n = gdb.parse_and_eval("called_from_pretty_printer ()")
        assert n == 23
        return "hahaha"

class Printer2:
    def to_string(self):
        n = gdb.parse_and_eval("called_from_pretty_printer ()")
        assert n == 23
        return "hohoho"

def lookup_function(val):
    if str(val.type) == 'struct type_1':
        return Printer1()

    if str(val.type) == 'struct type_2':
        return Printer2()

    return None

gdb.pretty_printers.append(lookup_function)
