1: 
2: void FUN_00132d40(long *param_1,int param_2)
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
16: return;
17: }
18: if (*(int *)(lVar1 + 0x7c) < param_2) {
19: return;
20: }
21: /* WARNING: Could not recover jumptable at 0x00132d55. Too many branches */
22: /* WARNING: Treating indirect jump as call */
23: (**(code **)(lVar1 + 0x10))();
24: return;
25: }
26: 
