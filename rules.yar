// SPDX-License-Identifier: MIT
// Author: Codex for Secure_Android, 2026-10-20.
// Static combinations for human review; NOT malware-family signatures.
rule Android_Dynamic_Dex_And_Shell : heuristic {
  meta:
    description = "Carga DEX y ejecución de shell en el mismo artefacto; usos legítimos posibles"
  strings:
    $dex = "Ldalvik/system/DexClassLoader;" ascii
    $exec = "Ljava/lang/Runtime;" ascii
    $shell = "/system/bin/sh" ascii
  condition: uint32(0) == 0x0a786564 and all of them
}
rule Native_Process_Inspection_And_Shell : heuristic {
  meta:
    description = "Biblioteca ELF con inspección de procesos y shell; no acredita explotación"
  strings:
    $ptrace = "ptrace" fullword ascii
    $proc = "/proc/" ascii
    $shell = "/system/bin/sh" ascii
  condition: uint32(0) == 0x464c457f and all of them
}
