1: 
2: void FUN_0014b810(code **param_1,char param_2)
3: 
4: {
5: long *plVar1;
6: char **ppcVar2;
7: code *pcVar3;
8: undefined *puVar4;
9: code **ppcVar5;
10: char **ppcVar6;
11: char *pcVar7;
12: code *pcVar8;
13: undefined (*pauVar9) [16];
14: int iVar10;
15: ulong uVar11;
16: long lVar12;
17: undefined8 *puVar13;
18: byte bVar14;
19: 
20: bVar14 = 0;
21: pcVar3 = param_1[0x3e];
22: FUN_0014b3d0();
23: puVar13 = (undefined8 *)param_1[5];
24: puVar4 = (undefined *)*puVar13;
25: *puVar13 = puVar4 + 1;
26: *puVar4 = 0xff;
27: plVar1 = puVar13 + 1;
28: *plVar1 = *plVar1 + -1;
29: if ((*plVar1 == 0) && (iVar10 = (*(code *)puVar13[3])(), iVar10 == 0)) {
30: ppcVar5 = (code **)*param_1;
31: *(undefined4 *)(ppcVar5 + 5) = 0x18;
32: (**ppcVar5)();
33: }
34: ppcVar6 = (char **)param_1[5];
35: pcVar7 = *ppcVar6;
36: *ppcVar6 = pcVar7 + 1;
37: *pcVar7 = param_2 + -0x30;
38: ppcVar2 = ppcVar6 + 1;
39: *ppcVar2 = *ppcVar2 + -1;
40: if ((*ppcVar2 == (char *)0x0) && (iVar10 = (*(code *)ppcVar6[3])(), iVar10 == 0)) {
41: ppcVar5 = (code **)*param_1;
42: *(undefined4 *)(ppcVar5 + 5) = 0x18;
43: (**ppcVar5)();
44: }
45: if (0 < *(int *)((long)param_1 + 0x144)) {
46: lVar12 = 1;
47: do {
48: pcVar8 = param_1[lVar12 + 0x28];
49: if ((*(int *)((long)param_1 + 0x134) == 0) ||
50: ((*(int *)((long)param_1 + 0x19c) == 0 && (*(int *)((long)param_1 + 0x1a4) == 0)))) {
51: pauVar9 = *(undefined (**) [16])(pcVar3 + (long)*(int *)(pcVar8 + 0x14) * 8 + 0x68);
52: *pauVar9 = (undefined  [16])0x0;
53: pauVar9[1] = (undefined  [16])0x0;
54: pauVar9[2] = (undefined  [16])0x0;
55: pauVar9[3] = (undefined  [16])0x0;
56: *(undefined4 *)(pcVar3 + lVar12 * 4 + 0x3c) = 0;
57: *(undefined4 *)(pcVar3 + lVar12 * 4 + 0x4c) = 0;
58: if (*(int *)((long)param_1 + 0x134) != 0) goto LAB_0014b990;
59: LAB_0014b912:
60: puVar13 = *(undefined8 **)(pcVar3 + (long)*(int *)(pcVar8 + 0x18) * 8 + 0xe8);
61: *puVar13 = 0;
62: puVar13[0x1f] = 0;
63: uVar11 = (ulong)(((int)puVar13 -
64: (int)(undefined8 *)((ulong)(puVar13 + 1) & 0xfffffffffffffff8)) + 0x100U >>
65: 3);
66: puVar13 = (undefined8 *)((ulong)(puVar13 + 1) & 0xfffffffffffffff8);
67: while (uVar11 != 0) {
68: uVar11 = uVar11 - 1;
69: *puVar13 = 0;
70: puVar13 = puVar13 + (ulong)bVar14 * -2 + 1;
71: }
72: }
73: else {
74: LAB_0014b990:
75: if (*(int *)(param_1 + 0x34) != 0) goto LAB_0014b912;
76: }
77: iVar10 = (int)lVar12;
78: lVar12 = lVar12 + 1;
79: } while (*(int *)((long)param_1 + 0x144) != iVar10 && iVar10 <= *(int *)((long)param_1 + 0x144))
80: ;
81: }
82: *(undefined8 *)(pcVar3 + 0x18) = 0;
83: *(undefined8 *)(pcVar3 + 0x20) = 0x10000;
84: *(undefined8 *)(pcVar3 + 0x28) = 0;
85: *(undefined8 *)(pcVar3 + 0x30) = 0;
86: *(undefined8 *)(pcVar3 + 0x38) = 0xffffffff0000000b;
87: return;
88: }
89: 
