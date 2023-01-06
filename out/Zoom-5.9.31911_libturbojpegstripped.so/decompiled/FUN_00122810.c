1: 
2: void FUN_00122810(long param_1,long *param_2,uint param_3,undefined8 *param_4,int param_5)
3: 
4: {
5: undefined *puVar1;
6: byte bVar2;
7: uint uVar3;
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
22: undefined8 *puStack72;
23: uint uStack64;
24: int iStack60;
25: 
26: lVar4 = *(long *)(param_1 + 0x268);
27: uVar3 = *(uint *)(param_1 + 0x88);
28: lVar5 = *(long *)(lVar4 + 0x10);
29: lVar6 = *(long *)(lVar4 + 0x18);
30: lVar7 = *(long *)(lVar4 + 0x20);
31: lVar4 = *(long *)(lVar4 + 0x28);
32: lVar8 = *(long *)(param_1 + 0x1a8);
33: puStack72 = param_4;
34: uStack64 = param_3;
35: iStack60 = param_5;
36: do {
37: iStack60 = iStack60 + -1;
38: if (iStack60 < 0) {
39: return;
40: }
41: while( true ) {
42: uVar14 = (ulong)uStack64;
43: puVar13 = puStack72 + 1;
44: uStack64 = uStack64 + 1;
45: lVar9 = *(long *)(*param_2 + uVar14 * 8);
46: lVar10 = *(long *)(param_2[1] + uVar14 * 8);
47: lVar11 = *(long *)(param_2[2] + uVar14 * 8);
48: lVar12 = *(long *)(param_2[3] + uVar14 * 8);
49: puVar16 = (undefined *)*puStack72;
50: lVar15 = 0;
51: puStack72 = puVar13;
52: if (uVar3 == 0) break;
53: do {
54: uVar17 = (ulong)*(byte *)(lVar11 + lVar15);
55: bVar2 = *(byte *)(lVar9 + lVar15);
56: uVar14 = (ulong)*(byte *)(lVar10 + lVar15);
57: *puVar16 = *(undefined *)
58: (lVar8 + (int)(0xff - (*(int *)(lVar5 + uVar17 * 4) + (uint)bVar2)));
59: puVar16[1] = *(undefined *)
60: (lVar8 + (int)(0xff - ((int)((ulong)(*(long *)(lVar4 + uVar14 * 8) +
61: *(long *)(lVar7 + uVar17 * 8)) >> 0x10) +
62: (uint)bVar2)));
63: puVar16[2] = *(undefined *)
64: (lVar8 + (int)(0xff - ((uint)bVar2 + *(int *)(lVar6 + uVar14 * 4))));
65: puVar1 = (undefined *)(lVar12 + lVar15);
66: lVar15 = lVar15 + 1;
67: puVar16[3] = *puVar1;
68: puVar16 = puVar16 + 4;
69: } while ((uint)lVar15 < uVar3);
70: iStack60 = iStack60 + -1;
71: if (iStack60 < 0) {
72: return;
73: }
74: }
75: } while( true );
76: }
77: 
