1: 
2: void FUN_0011c1b0(code **param_1,code *param_2)
3: 
4: {
5: code **ppcVar1;
6: bool bVar2;
7: code **ppcVar3;
8: code *pcVar4;
9: long lVar5;
10: int iVar6;
11: uint uVar7;
12: 
13: if (*(int *)((long)param_1 + 0x24) != 100) {
14: pcVar4 = *param_1;
15: *(int *)(pcVar4 + 0x2c) = *(int *)((long)param_1 + 0x24);
16: ppcVar3 = (code **)*param_1;
17: *(undefined4 *)(pcVar4 + 0x28) = 0x14;
18: (**ppcVar3)();
19: }
20: FUN_00102e40(param_1,0);
21: (**(code **)(*param_1 + 0x20))(param_1);
22: (**(code **)(param_1[5] + 0x10))(param_1);
23: *(undefined4 *)(param_1 + 7) = 1;
24: FUN_00116330(param_1,1);
25: if (*(int *)((long)param_1 + 0x104) == 0) {
26: if (*(int *)((long)param_1 + 0x134) == 0) {
27: FUN_00112400();
28: }
29: else {
30: FUN_0011a070();
31: }
32: }
33: else {
34: FUN_0013ffe0(param_1);
35: }
36: ppcVar3 = (code **)(**(code **)param_1[1])(param_1,1,0x78);
37: param_1[0x39] = (code *)ppcVar3;
38: ppcVar3[4] = param_2;
39: *ppcVar3 = FUN_0011c120;
40: ppcVar3[1] = FUN_0011b7c0;
41: pcVar4 = (code *)(**(code **)(param_1[1] + 8))(param_1,1,0x500);
42: FUN_0013bed0(pcVar4,0x500);
43: lVar5 = (long)(ppcVar3 + 5) << 0x3c;
44: if (-1 < lVar5) {
45: iVar6 = 10;
46: }
47: else {
48: ppcVar3[5] = pcVar4;
49: iVar6 = 9;
50: }
51: bVar2 = -1 >= lVar5;
52: uVar7 = (uint)bVar2;
53: ppcVar1 = ppcVar3 + (5 - (lVar5 >> 0x3f));
54: ppcVar1[2] = pcVar4 + (ulong)(bVar2 + 2) * 0x80;
55: ppcVar1[3] = pcVar4 + (ulong)(bVar2 + 3) * 0x80;
56: ppcVar1[4] = pcVar4 + (ulong)(uVar7 + 4) * 0x80;
57: ppcVar1[5] = pcVar4 + (ulong)(bVar2 + 5) * 0x80;
58: *ppcVar1 = pcVar4 + (ulong)uVar7 * 0x80;
59: ppcVar1[1] = pcVar4 + (ulong)(bVar2 + 1) * 0x80;
60: ppcVar1[6] = pcVar4 + (ulong)(bVar2 + 6) * 0x80;
61: ppcVar1[7] = pcVar4 + (ulong)(bVar2 + 7) * 0x80;
62: ppcVar3[(long)(int)(bVar2 + 8) + 5] = pcVar4 + (long)(int)(bVar2 + 8) * 0x80;
63: if (iVar6 != 9) {
64: ppcVar3[(long)(int)(bVar2 + 9) + 5] = pcVar4 + (long)(int)(bVar2 + 9) * 0x80;
65: if (iVar6 != 10) {
66: ppcVar3[(long)(int)(uVar7 + 10) + 5] = pcVar4 + (long)(int)(uVar7 + 10) * 0x80;
67: }
68: }
69: FUN_00115260(param_1);
70: (**(code **)(param_1[1] + 0x30))(param_1);
71: (**(code **)param_1[0x3a])(param_1);
72: *(undefined4 *)(param_1 + 0x26) = 0;
73: *(undefined4 *)((long)param_1 + 0x24) = 0x67;
74: return;
75: }
76: 
