import idautils

for mangled in idautils.Functions():
    demangled = idc.Demangle(
        str(idaapi.get_func_name(mangled)),
        idc.GetLongPrm(idc.INF_SHORT_DN)
    )
  
    if demangled is not None:
        print "{} => {}".format(mangled, demangled)
