1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: uint FUN_00168020(void)
5: 
6: {
7: uint uVar1;
8: ulong uVar2;
9: 
10: uVar2 = (ulong)_DAT_003a61e0;
11: if (_DAT_003a61e0 == 0xffffffff) {
12: FUN_00167b80();
13: uVar2 = (ulong)_DAT_003a61e0;
14: }
15: uVar1 = 1;
16: if ((uVar2 & 0x80) == 0) {
17: uVar1 = (uint)(uVar2 >> 3) & 1;
18: }
19: return uVar1;
20: }
21: 
