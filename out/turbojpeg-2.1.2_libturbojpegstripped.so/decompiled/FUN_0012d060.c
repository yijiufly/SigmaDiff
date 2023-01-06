1: 
2: void FUN_0012d060(long param_1,long *param_2,uint param_3,undefined8 *param_4,int param_5)
3: 
4: {
5: undefined *puVar1;
6: byte bVar2;
7: int iVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: long lVar7;
12: long lVar8;
13: long lVar9;
14: long lVar10;
15: long lVar11;
16: long lVar12;
17: undefined8 *puVar13;
18: ulong uVar14;
19: long lVar15;
20: undefined *puVar16;
21: ulong uVar17;
22: 
23: lVar4 = *(long *)(param_1 + 0x268);
24: iVar3 = *(int *)(param_1 + 0x88);
25: lVar5 = *(long *)(param_1 + 0x1a8);
26: lVar6 = *(long *)(lVar4 + 0x20);
27: lVar7 = *(long *)(lVar4 + 0x10);
28: lVar8 = *(long *)(lVar4 + 0x18);
29: lVar4 = *(long *)(lVar4 + 0x28);
30: while (param_5 = param_5 + -1, -1 < param_5) {
31: uVar14 = (ulong)param_3;
32: puVar13 = param_4 + 1;
33: lVar9 = *(long *)(*param_2 + uVar14 * 8);
34: param_3 = param_3 + 1;
35: lVar10 = *(long *)(param_2[1] + uVar14 * 8);
36: lVar11 = *(long *)(param_2[2] + uVar14 * 8);
37: lVar12 = *(long *)(param_2[3] + uVar14 * 8);
38: puVar16 = (undefined *)*param_4;
39: param_4 = puVar13;
40: if (iVar3 != 0) {
41: lVar15 = 0;
42: do {
43: uVar17 = (ulong)*(byte *)(lVar11 + lVar15);
44: bVar2 = *(byte *)(lVar9 + lVar15);
45: uVar14 = (ulong)*(byte *)(lVar10 + lVar15);
46: *puVar16 = *(undefined *)
47: (lVar5 + (int)(0xff - (*(int *)(lVar7 + uVar17 * 4) + (uint)bVar2)));
48: puVar16[1] = *(undefined *)
49: (lVar5 + (int)(0xff - ((int)((ulong)(*(long *)(lVar6 + uVar17 * 8) +
50: *(long *)(lVar4 + uVar14 * 8)) >> 0x10) +
51: (uint)bVar2)));
52: puVar16[2] = *(undefined *)
53: (lVar5 + (int)(0xff - ((uint)bVar2 + *(int *)(lVar8 + uVar14 * 4))));
54: puVar1 = (undefined *)(lVar12 + lVar15);
55: lVar15 = lVar15 + 1;
56: puVar16[3] = *puVar1;
57: puVar16 = puVar16 + 4;
58: } while (lVar15 != (ulong)(iVar3 - 1) + 1);
59: }
60: }
61: return;
62: }
63: 
