1: 
2: code ** FUN_0016bd50(long param_1)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: code *pcVar3;
8: 
9: ppcVar2 = (code **)(***(code ***)(param_1 + 8))(param_1,1,0x58);
10: *ppcVar2 = FUN_0016bc90;
11: ppcVar2[2] = FUN_0016bc40;
12: ppcVar2[3] = FUN_0016b950;
13: FUN_00136eb0(param_1);
14: (*ppcVar2[3])(param_1,ppcVar2);
15: pcVar3 = (code *)(***(code ***)(param_1 + 8))(param_1,1,ppcVar2[9]);
16: iVar1 = *(int *)(param_1 + 0x6c);
17: ppcVar2[7] = pcVar3;
18: if ((iVar1 == 0) && ((*(uint *)(param_1 + 0x40) & 0xfffffffb) == 2)) {
19: ppcVar2[8] = pcVar3;
20: *(undefined4 *)(ppcVar2 + 6) = 1;
21: ppcVar2[5] = (code *)(ppcVar2 + 8);
22: ppcVar2[1] = FUN_0016b990;
23: }
24: else {
25: pcVar3 = (code *)(**(code **)(*(long *)(param_1 + 8) + 0x10))
26: (param_1,1,*(int *)(param_1 + 0x88) * *(int *)(param_1 + 0x94),1);
27: ppcVar2[5] = pcVar3;
28: iVar1 = *(int *)(param_1 + 0x6c);
29: *(undefined4 *)(ppcVar2 + 6) = 1;
30: if (iVar1 == 0) {
31: iVar1 = *(int *)(param_1 + 0x40);
32: if ((iVar1 - 6U < 10) || (iVar1 == 2)) {
33: ppcVar2[1] = FUN_0016bb70;
34: return ppcVar2;
35: }
36: if (iVar1 != 4) {
37: ppcVar2[1] = FUN_0016bc10;
38: return ppcVar2;
39: }
40: ppcVar2[1] = FUN_0016baa0;
41: }
42: else {
43: if (*(int *)(param_1 + 0x40) == 1) {
44: ppcVar2[1] = FUN_0016ba30;
45: return ppcVar2;
46: }
47: ppcVar2[1] = FUN_0016b9b0;
48: }
49: }
50: return ppcVar2;
51: }
52: 
