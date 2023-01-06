1: 
2: void FUN_0011f500(long param_1)
3: 
4: {
5: int iVar1;
6: long lVar2;
7: bool bVar3;
8: short *psVar4;
9: int *piVar5;
10: long lVar6;
11: long lVar7;
12: int iVar8;
13: long lVar9;
14: 
15: lVar2 = *(long *)(param_1 + 0x230);
16: if (*(long *)(lVar2 + 0x20) != 0) {
17: if (((*(int *)(param_1 + 0x68) != 0) && (*(int *)(param_1 + 0x138) != 0)) &&
18: (*(long *)(param_1 + 0xc0) != 0)) {
19: lVar6 = *(long *)(lVar2 + 0xe0);
20: if (lVar6 == 0) {
21: lVar6 = (***(code ***)(param_1 + 8))(param_1,1,(long)*(int *)(param_1 + 0x38) * 0x18);
22: *(long *)(lVar2 + 0xe0) = lVar6;
23: }
24: if ((((0 < *(int *)(param_1 + 0x38)) &&
25: (psVar4 = *(short **)(*(long *)(param_1 + 0x130) + 0x50), psVar4 != (short *)0x0)) &&
26: ((*psVar4 != 0 && ((psVar4[1] != 0 && (psVar4[8] != 0)))))) && (psVar4[0x10] != 0)) {
27: lVar9 = 0;
28: bVar3 = false;
29: iVar8 = 0;
30: lVar7 = *(long *)(param_1 + 0x130);
31: while( true ) {
32: if (((psVar4[9] == 0) || (psVar4[2] == 0)) ||
33: (piVar5 = (int *)(lVar9 + *(long *)(param_1 + 0xc0)), *piVar5 < 0)) goto LAB_0011f51e;
34: *(int *)(lVar6 + 4) = piVar5[1];
35: if (piVar5[1] != 0) {
36: bVar3 = true;
37: }
38: *(int *)(lVar6 + 8) = piVar5[2];
39: iVar1 = piVar5[2];
40: *(int *)(lVar6 + 0xc) = piVar5[3];
41: if (iVar1 != 0) {
42: bVar3 = true;
43: }
44: if (piVar5[3] != 0) {
45: bVar3 = true;
46: }
47: *(int *)(lVar6 + 0x10) = piVar5[4];
48: iVar1 = piVar5[4];
49: *(int *)(lVar6 + 0x14) = piVar5[5];
50: if (iVar1 != 0) {
51: bVar3 = true;
52: }
53: if (piVar5[5] != 0) {
54: bVar3 = true;
55: }
56: lVar6 = lVar6 + 0x18;
57: iVar8 = iVar8 + 1;
58: if (*(int *)(param_1 + 0x38) <= iVar8) break;
59: psVar4 = *(short **)(lVar7 + 0xb0);
60: if (((psVar4 == (short *)0x0) || (*psVar4 == 0)) ||
61: ((psVar4[1] == 0 ||
62: ((psVar4[8] == 0 || (lVar9 = lVar9 + 0x100, lVar7 = lVar7 + 0x60, psVar4[0x10] == 0)))
63: ))) goto LAB_0011f51e;
64: }
65: if (bVar3) {
66: *(code **)(lVar2 + 0x18) = FUN_0011f6d0;
67: goto LAB_0011f529;
68: }
69: }
70: }
71: LAB_0011f51e:
72: *(code **)(lVar2 + 0x18) = FUN_0011f2e0;
73: }
74: LAB_0011f529:
75: *(undefined4 *)(param_1 + 0xb8) = 0;
76: return;
77: }
78: 
