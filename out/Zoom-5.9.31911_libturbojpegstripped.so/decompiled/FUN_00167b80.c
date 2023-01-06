1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: void FUN_00167b80(void)
5: 
6: {
7: uint uVar1;
8: char *pcVar2;
9: 
10: uVar1 = FUN_001550a0();
11: _DAT_003a61e0 = uVar1;
12: pcVar2 = getenv("JSIMD_FORCESSE2");
13: if (((pcVar2 != (char *)0x0) && (*pcVar2 == '1')) && (pcVar2[1] == '\0')) {
14: uVar1 = uVar1 & 8;
15: _DAT_003a61e0 = uVar1;
16: }
17: pcVar2 = getenv("JSIMD_FORCEAVX2");
18: if (((pcVar2 != (char *)0x0) && (*pcVar2 == '1')) && (pcVar2[1] == '\0')) {
19: _DAT_003a61e0 = uVar1 & 0x80;
20: }
21: pcVar2 = getenv("JSIMD_FORCENONE");
22: if (((pcVar2 != (char *)0x0) && (*pcVar2 == '1')) && (pcVar2[1] == '\0')) {
23: _DAT_003a61e0 = 0;
24: }
25: pcVar2 = getenv("JSIMD_NOHUFFENC");
26: if (((pcVar2 != (char *)0x0) && (*pcVar2 == '1')) && (pcVar2[1] == '\0')) {
27: _DAT_003a61d0 = 0;
28: }
29: return;
30: }
31: 
