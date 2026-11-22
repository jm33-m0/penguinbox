rule PenguinBox_ProcMaps
{
    meta:
        severity = "high"
        source = "penguinbox"
        description = "reads the process memory map"
    strings:
        $a = "/proc/self/maps" ascii
    condition:
        $a
}

rule PenguinBox_Memfd
{
    meta:
        severity = "high"
        source = "penguinbox"
        description = "creates an anonymous executable backing file"
    strings:
        $a = "memfd_create" ascii
    condition:
        $a
}

rule PenguinBox_Ptrace
{
    meta:
        severity = "medium"
        source = "penguinbox"
        description = "references ptrace"
    strings:
        $a = "ptrace" ascii
    condition:
        $a
}
