1: 
2: bool FUN_0014f700(uint param_1,uint param_2,uint param_3,uint param_4,int param_5)
3: 
4: {
5: ulong uVar1;
6: bool bVar2;
7: 
8: bVar2 = true;
9: if (param_5 - 1U < 7) {
10: uVar1 = 1 << ((byte)(param_5 - 1U) & 0x3f);
11: if ((uVar1 & 0x28) == 0) {
12: if ((uVar1 & 0x12) != 0) {
13: return param_2 % param_4 == 0;
14: }
15: if ((uVar1 & 0x41) == 0) {
16: return true;
17: }
18: }
19: else {
20: if (param_2 % param_4 != 0) {
21: return false;
22: }
23: }
24: bVar2 = param_1 % param_3 == 0;
25: }
26: return bVar2;
27: }
28: 