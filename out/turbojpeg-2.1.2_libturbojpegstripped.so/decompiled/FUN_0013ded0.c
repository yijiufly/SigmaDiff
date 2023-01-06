1: 
2: void FUN_0013ded0(long *param_1,int param_2)
3: 
4: {
5: long lVar1;
6: long lVar2;
7: 
8: lVar1 = *param_1;
9: if (param_2 < 0) {
10: lVar2 = *(long *)(lVar1 + 0x80);
11: if ((lVar2 == 0) || (2 < *(int *)(lVar1 + 0x7c))) {
12: (**(code **)(lVar1 + 0x10))();
13: lVar2 = *(long *)(lVar1 + 0x80);
14: }
15: *(long *)(lVar1 + 0x80) = lVar2 + 1;
16: }
17: else {
18: if (param_2 <= *(int *)(lVar1 + 0x7c)) {
19: /* WARNING: Could not recover jumptable at 0x0013dee2. Too many branches */
20: /* WARNING: Treating indirect jump as call */
21: (**(code **)(lVar1 + 0x10))();
22: return;
23: }
24: }
25: return;
26: }
27: 
