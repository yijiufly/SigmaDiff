1: 
2: void FUN_00167210(long param_1,long param_2)
3: 
4: {
5: long *plVar1;
6: long lVar2;
7: 
8: if (0 < param_2) {
9: plVar1 = *(long **)(param_1 + 0x28);
10: lVar2 = plVar1[1];
11: if (lVar2 < param_2) {
12: do {
13: param_2 = param_2 - lVar2;
14: (*(code *)plVar1[3])(param_1);
15: lVar2 = plVar1[1];
16: } while (lVar2 < param_2);
17: }
18: *plVar1 = *plVar1 + param_2;
19: plVar1[1] = lVar2 - param_2;
20: return;
21: }
22: return;
23: }
24: 
