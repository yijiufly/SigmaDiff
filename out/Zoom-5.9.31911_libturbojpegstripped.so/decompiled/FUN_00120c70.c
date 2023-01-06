1: 
2: void FUN_00120c70(long param_1,long *param_2,uint param_3,long *param_4,int param_5)
3: 
4: {
5: uint uVar1;
6: long lVar2;
7: long lVar3;
8: long lVar4;
9: long lVar5;
10: long lVar6;
11: ulong uVar7;
12: long *plVar8;
13: long lVar9;
14: 
15: uVar1 = *(uint *)(param_1 + 0x88);
16: lVar2 = *(long *)(*(long *)(param_1 + 0x268) + 0x30);
17: do {
18: param_5 = param_5 + -1;
19: plVar8 = param_4;
20: if (param_5 < 0) {
21: return;
22: }
23: while( true ) {
24: uVar7 = (ulong)param_3;
25: param_4 = plVar8 + 1;
26: param_3 = param_3 + 1;
27: lVar3 = *plVar8;
28: lVar4 = *(long *)(*param_2 + uVar7 * 8);
29: lVar5 = *(long *)(param_2[1] + uVar7 * 8);
30: lVar6 = *(long *)(param_2[2] + uVar7 * 8);
31: lVar9 = 0;
32: if (uVar1 == 0) break;
33: do {
34: *(char *)(lVar3 + lVar9) =
35: (char)((ulong)(*(long *)(lVar2 + (ulong)*(byte *)(lVar4 + lVar9) * 8) +
36: *(long *)(lVar2 + 0x800 + (ulong)*(byte *)(lVar5 + lVar9) * 8) +
37: *(long *)(lVar2 + 0x1000 + (ulong)*(byte *)(lVar6 + lVar9) * 8)) >> 0x10)
38: ;
39: lVar9 = lVar9 + 1;
40: } while ((uint)lVar9 < uVar1);
41: param_5 = param_5 + -1;
42: plVar8 = param_4;
43: if (param_5 < 0) {
44: return;
45: }
46: }
47: } while( true );
48: }
49: 
