1: 
2: void FUN_00114210(long *param_1)
3: 
4: {
5: bool bVar1;
6: int iVar2;
7: long lVar3;
8: long lVar4;
9: int iVar5;
10: undefined8 uVar6;
11: int iVar7;
12: 
13: iVar7 = 0;
14: iVar2 = *(int *)((long)param_1 + 0x4c);
15: if (0 < iVar2) {
16: iVar5 = 0;
17: do {
18: iVar5 = iVar5 + 1;
19: iVar2 = FUN_00113f30();
20: iVar7 = iVar7 + iVar2;
21: iVar2 = *(int *)((long)param_1 + 0x4c);
22: } while (iVar5 < iVar2);
23: }
24: if (*(int *)((long)param_1 + 0x104) != 0) {
25: LAB_0011425a:
26: if (*(int *)((long)param_1 + 0x134) == 0) {
27: uVar6 = 0xc9;
28: }
29: else {
30: uVar6 = 0xca;
31: }
32: goto LAB_0011426b;
33: }
34: if (*(int *)((long)param_1 + 0x134) != 0) {
35: LAB_0011428c:
36: uVar6 = 0xc2;
37: goto LAB_0011426b;
38: }
39: if (*(int *)(param_1 + 9) == 8) {
40: lVar4 = param_1[0xb];
41: if (iVar2 < 1) {
42: bVar1 = true;
43: LAB_0011431f:
44: if (iVar7 != 0) {
45: lVar4 = *param_1;
46: *(undefined4 *)(lVar4 + 0x28) = 0x4b;
47: (**(code **)(lVar4 + 8))(param_1);
48: if (*(int *)((long)param_1 + 0x104) != 0) goto LAB_0011425a;
49: if (*(int *)((long)param_1 + 0x134) != 0) goto LAB_0011428c;
50: goto LAB_001142a0;
51: }
52: }
53: else {
54: bVar1 = true;
55: lVar3 = ((ulong)(iVar2 - 1) * 3 + 3) * 0x20 + lVar4;
56: do {
57: if (*(int *)(lVar4 + 0x14) < 2) {
58: if (1 < *(int *)(lVar4 + 0x18)) {
59: bVar1 = false;
60: }
61: }
62: else {
63: bVar1 = false;
64: }
65: lVar4 = lVar4 + 0x60;
66: } while (lVar4 != lVar3);
67: if (bVar1) goto LAB_0011431f;
68: }
69: uVar6 = 0xc0;
70: if (!bVar1) {
71: uVar6 = 0xc1;
72: }
73: }
74: else {
75: LAB_001142a0:
76: uVar6 = 0xc1;
77: }
78: LAB_0011426b:
79: FUN_00112bb0(param_1,uVar6);
80: return;
81: }
82: 
