1: 
2: /* WARNING: Removing unreachable block (ram,0x001550d7) */
3: /* WARNING: Removing unreachable block (ram,0x001550c2) */
4: /* WARNING: Removing unreachable block (ram,0x001550b2) */
5: 
6: undefined  [16] FUN_001550a0(void)
7: 
8: {
9: uint *puVar1;
10: long lVar2;
11: ulong uVar3;
12: undefined8 uVar4;
13: uint in_XCR0;
14: uint in_register_00000604;
15: 
16: uVar4 = 0xc;
17: puVar1 = (uint *)cpuid_basic_info(0);
18: uVar3 = (ulong)puVar1[2];
19: if (6 < *puVar1) {
20: lVar2 = cpuid_Extended_Feature_Enumeration_info(7);
21: uVar3 = (ulong)*(uint *)(lVar2 + 8);
22: if ((*(uint *)(lVar2 + 4) & 0x20) != 0) {
23: lVar2 = cpuid_Version_info(1);
24: uVar3 = (ulong)*(uint *)(lVar2 + 8);
25: if ((((*(uint *)(lVar2 + 0xc) & 0x8000000) != 0) &&
26: ((*(uint *)(lVar2 + 0xc) & 0x10000000) != 0)) &&
27: (uVar3 = (ulong)in_register_00000604, (in_XCR0 & 6) == 6)) {
28: uVar4 = 0x8c;
29: }
30: }
31: }
32: return CONCAT88(uVar3,uVar4);
33: }
34: 
