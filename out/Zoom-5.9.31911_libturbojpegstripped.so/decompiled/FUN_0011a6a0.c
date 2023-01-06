1: 
2: void FUN_0011a6a0(code **param_1,int param_2)
3: 
4: {
5: uint *puVar1;
6: int *piVar2;
7: code **ppcVar3;
8: code **ppcVar4;
9: code *pcVar5;
10: undefined8 *puVar6;
11: undefined8 *__src;
12: undefined8 *puVar7;
13: code *pcVar8;
14: int iVar9;
15: int iVar10;
16: 
17: if (param_2 != 0) {
18: ppcVar4 = (code **)*param_1;
19: *(undefined4 *)(ppcVar4 + 5) = 4;
20: (**ppcVar4)();
21: }
22: ppcVar4 = (code **)(**(code **)param_1[1])(param_1,1,0x70);
23: param_1[0x38] = (code *)ppcVar4;
24: *ppcVar4 = FUN_0011a100;
25: if (*(int *)(param_1[0x3c] + 0x10) == 0) {
26: pcVar8 = param_1[0xb];
27: ppcVar4[1] = FUN_0011a150;
28: if (0 < *(int *)((long)param_1 + 0x4c)) {
29: iVar9 = 0;
30: do {
31: puVar1 = (uint *)(pcVar8 + 0x1c);
32: piVar2 = (int *)(pcVar8 + 8);
33: iVar9 = iVar9 + 1;
34: pcVar8 = pcVar8 + 0x60;
35: pcVar5 = (code *)(**(code **)(param_1[1] + 0x10))
36: (param_1,1,
37: (long)((ulong)*puVar1 * 8 * (long)*(int *)(param_1 + 0x27)) /
38: (long)*piVar2 & 0xffffffff,
39: *(undefined4 *)((long)param_1 + 0x13c));
40: ppcVar4[2] = pcVar5;
41: ppcVar4 = ppcVar4 + 1;
42: } while (*(int *)((long)param_1 + 0x4c) != iVar9 && iVar9 <= *(int *)((long)param_1 + 0x4c));
43: }
44: }
45: else {
46: ppcVar3 = (code **)param_1[1];
47: ppcVar4[1] = FUN_0011a3f0;
48: iVar9 = *(int *)((long)param_1 + 0x13c);
49: puVar6 = (undefined8 *)
50: (**ppcVar3)(param_1,1,(long)(*(int *)((long)param_1 + 0x4c) * 5 * iVar9) << 3);
51: pcVar8 = param_1[0xb];
52: if (0 < *(int *)((long)param_1 + 0x4c)) {
53: iVar10 = 0;
54: do {
55: __src = (undefined8 *)
56: (**(code **)(param_1[1] + 0x10))
57: (param_1,1,
58: (long)((ulong)*(uint *)(pcVar8 + 0x1c) * 8 *
59: (long)*(int *)(param_1 + 0x27)) / (long)*(int *)(pcVar8 + 8) &
60: 0xffffffff,iVar9 * 3);
61: pcVar5 = (code *)memcpy(puVar6 + iVar9,__src,(long)(iVar9 * 3) << 3);
62: puVar7 = puVar6;
63: if (0 < iVar9) {
64: do {
65: *puVar7 = __src[iVar9 * 2];
66: puVar7[iVar9 * 4] = *__src;
67: puVar7 = puVar7 + 1;
68: __src = __src + 1;
69: } while (puVar7 != puVar6 + (ulong)(iVar9 - 1) + 1);
70: }
71: ppcVar4[2] = pcVar5;
72: puVar6 = puVar6 + iVar9 * 5;
73: iVar10 = iVar10 + 1;
74: pcVar8 = pcVar8 + 0x60;
75: ppcVar4 = ppcVar4 + 1;
76: } while (iVar10 < *(int *)((long)param_1 + 0x4c));
77: return;
78: }
79: }
80: return;
81: }
82: 
