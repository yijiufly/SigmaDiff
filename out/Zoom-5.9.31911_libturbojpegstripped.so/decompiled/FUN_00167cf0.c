1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8 FUN_00167cf0(void)
5: 
6: {
7: undefined8 uVar1;
8: 
9: if (_DAT_003a61e0 == 0xffffffff) {
10: FUN_00167b80();
11: }
12: if ((_DAT_003a61e0 & 0x80) == 0) {
13: uVar1 = 0;
14: if ((_DAT_003a61e0 & 8) != 0) {
15: return 1;
16: }
17: }
18: else {
19: uVar1 = 1;
20: }
21: return uVar1;
22: }
23: 
