1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: uint FUN_00168a10(void)
5: 
6: {
7: if (_DAT_003a61e0 != 0xffffffff) {
8: return _DAT_003a61e0 >> 3 & 1;
9: }
10: FUN_00167b80();
11: return _DAT_003a61e0 >> 3 & 1;
12: }
13: 
