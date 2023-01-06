1: 
2: undefined8 FUN_00169650(code **param_1,long param_2)
3: 
4: {
5: uint uVar1;
6: int iVar2;
7: int iVar3;
8: int iVar4;
9: int iVar5;
10: int iVar6;
11: int iVar7;
12: long lVar8;
13: code **ppcVar9;
14: ushort *puVar10;
15: ulong uVar11;
16: size_t sVar12;
17: undefined *puVar13;
18: ushort uVar14;
19: undefined *puVar15;
20: ushort *puVar16;
21: ushort *puVar17;
22: 
23: uVar11 = (ulong)*(uint *)((long)param_1 + 0x3c);
24: lVar8 = *(long *)(param_2 + 0x48);
25: uVar1 = *(uint *)(param_2 + 0x50);
26: iVar2 = *(int *)(&DAT_00190860 + uVar11 * 4);
27: iVar3 = *(int *)(&DAT_00190800 + uVar11 * 4);
28: iVar4 = *(int *)(&DAT_001907a0 + uVar11 * 4);
29: iVar5 = *(int *)(&DAT_001906e0 + uVar11 * 4);
30: iVar6 = *(int *)(&DAT_00190740 + uVar11 * 4);
31: sVar12 = fread(*(void **)(param_2 + 0x30),1,*(size_t *)(param_2 + 0x40),*(FILE **)(param_2 + 0x18)
32: );
33: if (*(size_t *)(param_2 + 0x40) != sVar12) {
34: ppcVar9 = (code **)*param_1;
35: *(undefined4 *)(ppcVar9 + 5) = 0x2b;
36: (**ppcVar9)(param_1);
37: }
38: puVar10 = *(ushort **)(param_2 + 0x30);
39: iVar7 = *(int *)(param_1 + 6);
40: if (iVar7 != 0) {
41: puVar13 = (undefined *)(**(long **)(param_2 + 0x20) + (long)iVar4);
42: puVar16 = puVar10;
43: do {
44: uVar14 = *puVar16 << 8 | *puVar16 >> 8;
45: if (uVar1 < uVar14) {
46: ppcVar9 = (code **)*param_1;
47: *(undefined4 *)(ppcVar9 + 5) = 0x3f9;
48: (**ppcVar9)(param_1);
49: }
50: puVar15 = puVar13 + -(long)iVar4;
51: puVar15[iVar2] = *(undefined *)(lVar8 + (ulong)uVar14);
52: uVar14 = puVar16[1] << 8 | puVar16[1] >> 8;
53: if (uVar1 < uVar14) {
54: ppcVar9 = (code **)*param_1;
55: *(undefined4 *)(ppcVar9 + 5) = 0x3f9;
56: (**ppcVar9)(param_1);
57: }
58: puVar17 = puVar16 + 3;
59: puVar15[iVar3] = *(undefined *)(lVar8 + (ulong)uVar14);
60: uVar14 = puVar16[2] << 8 | puVar16[2] >> 8;
61: if (uVar1 < uVar14) {
62: ppcVar9 = (code **)*param_1;
63: *(undefined4 *)(ppcVar9 + 5) = 0x3f9;
64: (**ppcVar9)(param_1);
65: }
66: *puVar13 = *(undefined *)(lVar8 + (ulong)uVar14);
67: if (-1 < iVar5) {
68: puVar15[iVar5] = 0xff;
69: }
70: puVar13 = puVar13 + iVar6;
71: puVar16 = puVar17;
72: } while (puVar10 + (ulong)(iVar7 - 1) * 3 + 3 != puVar17);
73: }
74: return 1;
75: }
76: 
