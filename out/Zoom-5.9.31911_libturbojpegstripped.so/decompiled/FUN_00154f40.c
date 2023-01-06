1: 
2: code ** FUN_00154f40(long param_1)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: code *pcVar3;
8: 
9: ppcVar2 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x58);
10: *ppcVar2 = FUN_00154e20;
11: ppcVar2[2] = FUN_00154ef0;
12: ppcVar2[3] = FUN_00154b40;
13: FUN_0012c110(param_1);
14: (*ppcVar2[3])(param_1,ppcVar2);
15: pcVar3 = (code *)(***(code ***)(param_1 + 8))(param_1,1,ppcVar2[9]);
16: iVar1 = *(int *)(param_1 + 0x6c);
17: ppcVar2[7] = pcVar3;
18: if ((iVar1 == 0) && ((*(uint *)(param_1 + 0x40) & 0xfffffffb) == 2)) {
19: ppcVar2[8] = pcVar3;
20: *(undefined4 *)(ppcVar2 + 6) = 1;
21: ppcVar2[5] = (code *)(ppcVar2 + 8);
22: ppcVar2[1] = FUN_00154b80;
23: return ppcVar2;
24: }
25: pcVar3 = (code *)(**(code **)(*(long *)(param_1 + 8) + 0x10))
26: (param_1,1,*(int *)(param_1 + 0x94) * *(int *)(param_1 + 0x88),1);
27: ppcVar2[5] = pcVar3;
28: iVar1 = *(int *)(param_1 + 0x6c);
29: *(undefined4 *)(ppcVar2 + 6) = 1;
30: if (iVar1 != 0) {
31: pcVar3 = FUN_00154c20;
32: if (*(int *)(param_1 + 0x40) != 1) {
33: pcVar3 = FUN_00154ba0;
34: }
35: ppcVar2[1] = pcVar3;
36: return ppcVar2;
37: }
38: iVar1 = *(int *)(param_1 + 0x40);
39: if ((9 < iVar1 - 6U) && (iVar1 != 2)) {
40: pcVar3 = FUN_00154c90;
41: if (iVar1 != 4) {
42: pcVar3 = FUN_00154df0;
43: }
44: ppcVar2[1] = pcVar3;
45: return ppcVar2;
46: }
47: ppcVar2[1] = FUN_00154d50;
48: return ppcVar2;
49: }
50: 
