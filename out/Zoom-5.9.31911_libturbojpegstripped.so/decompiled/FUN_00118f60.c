1: 
2: undefined8 FUN_00118f60(code **param_1,long param_2)
3: 
4: {
5: long *plVar1;
6: byte bVar2;
7: undefined4 uVar3;
8: code *pcVar4;
9: undefined8 uVar5;
10: code *pcVar6;
11: code **ppcVar7;
12: undefined8 *puVar8;
13: int iVar9;
14: uint uVar10;
15: int iVar11;
16: long lVar12;
17: long lVar13;
18: uint uVar14;
19: uint uVar15;
20: byte bStack76;
21: 
22: uVar3 = *(undefined4 *)(param_1 + 0x35);
23: iVar9 = *(int *)(param_1 + 0x23);
24: pcVar4 = param_1[0x3e];
25: uVar5 = *(undefined8 *)((long)param_1[5] + 8);
26: *(undefined8 *)(pcVar4 + 0x30) = *(undefined8 *)param_1[5];
27: *(undefined8 *)(pcVar4 + 0x38) = uVar5;
28: if ((iVar9 != 0) && (*(int *)(pcVar4 + 0x80) == 0)) {
29: FUN_00118d20(pcVar4,*(undefined4 *)(pcVar4 + 0x84));
30: }
31: lVar13 = 0;
32: if (0 < *(int *)(param_1 + 0x2e)) {
33: do {
34: lVar12 = (long)*(int *)((long)param_1 + lVar13 * 4 + 0x174);
35: bStack76 = (byte)uVar3;
36: pcVar6 = param_1[lVar12 + 0x29];
37: iVar9 = (int)**(short **)(param_2 + lVar13 * 8) >> (bStack76 & 0x1f);
38: uVar14 = iVar9 - *(int *)(pcVar4 + lVar12 * 4 + 0x58);
39: *(int *)(pcVar4 + lVar12 * 4 + 0x58) = iVar9;
40: uVar10 = (int)uVar14 >> 0x1f;
41: uVar15 = (uVar14 ^ uVar10) - uVar10;
42: bVar2 = (&DAT_00179440)[(int)uVar15];
43: uVar14 = (uint)bVar2;
44: if (0xb < uVar14) {
45: ppcVar7 = (code **)*param_1;
46: *(undefined4 *)(ppcVar7 + 5) = 6;
47: (**ppcVar7)(param_1);
48: }
49: if (*(int *)(pcVar4 + 0x28) == 0) {
50: FUN_00118500(pcVar4,*(undefined4 *)
51: (*(long *)(pcVar4 + (long)*(int *)(pcVar6 + 0x14) * 8 + 0x88) +
52: (long)(int)uVar14 * 4),
53: (int)*(char *)(*(long *)(pcVar4 + (long)*(int *)(pcVar6 + 0x14) * 8 + 0x88) +
54: 0x400 + (long)(int)uVar14));
55: if (bVar2 != 0) {
56: LAB_00119085:
57: FUN_00118500(pcVar4,uVar15 ^ uVar10,uVar14);
58: }
59: }
60: else {
61: plVar1 = (long *)(*(long *)(pcVar4 + (long)*(int *)(pcVar6 + 0x14) * 8 + 0xa8) +
62: (ulong)bVar2 * 8);
63: *plVar1 = *plVar1 + 1;
64: if (uVar14 != 0) goto LAB_00119085;
65: }
66: iVar9 = (int)lVar13 + 1;
67: lVar13 = lVar13 + 1;
68: } while (*(int *)(param_1 + 0x2e) != iVar9 && iVar9 <= *(int *)(param_1 + 0x2e));
69: }
70: puVar8 = (undefined8 *)param_1[5];
71: *puVar8 = *(undefined8 *)(pcVar4 + 0x30);
72: puVar8[1] = *(undefined8 *)(pcVar4 + 0x38);
73: iVar9 = *(int *)(param_1 + 0x23);
74: if (iVar9 != 0) {
75: iVar11 = *(int *)(pcVar4 + 0x80);
76: if (*(int *)(pcVar4 + 0x80) == 0) {
77: *(uint *)(pcVar4 + 0x84) = *(int *)(pcVar4 + 0x84) + 1U & 7;
78: iVar11 = iVar9;
79: }
80: *(int *)(pcVar4 + 0x80) = iVar11 + -1;
81: }
82: return 1;
83: }
84: 
