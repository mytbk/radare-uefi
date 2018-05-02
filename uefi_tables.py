rtsvcs = [ "GetTime", "SetTime", "GetWakeupTime", "SetWakeupTime",
        "SetVirtualAddressMap", "ConvertPointer", "GetVariable", "GetNextVariableName",
        "SetVariable", "GetNextHighMonotonicCount", "ResetSystem", "UpdateCapsule",
        "QueryCapsuleCapabilities", "QueryVariableInfo" ]

def rt_svc_name(addr):
    if (addr > 0x80):
        return None
    return rtsvcs[(addr-0x18)//8]

bsvcs = [ "RaiseTPL", "RestoreTPL", "AllocatePages", "FreePages",
        "GetMemoryMap", "AllocatePool", "FreePool", "CreateEvent",
        "SetTimer", "WaitForEvent", "SignalEvent", "CloseEvent",
        "CheckEvent", "InstallProtocolInterface", "ReinstallProtocolInterface", "UninstallProtocolInterface",
        "HandleProtocol", "<Reserved>", "RegisterProtocolNotify", "LocateHandle",
        "LocateDevicePath", "InstallConfigurationTable", "LoadImage", "StartImage",
        "Exit", "UnloadImage", "ExitBootServices", "GetNextHighMonotonicCount",
        "Stall", "SetWatchdogTimer", "ConnectController", "DisconnectController",
        "OpenProtocol", "CloseProtocol", "OpenProtocolInformation", "ProtocolsPerHandle",
        "LocateHandleBuffer", "LocateProtocol", "InstallMultipleProtocolInterfaces", "UninstallMultipleProtocolInterfaces",
        "CalculateCrc32", "CopyMem", "SetMem", "CreateEventEx" ]

def boot_svc_name(addr):
    if (addr > 0x170):
        return None
    return bsvcs[(addr-0x18)//8]

