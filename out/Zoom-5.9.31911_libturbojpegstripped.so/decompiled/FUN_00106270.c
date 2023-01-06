1: 
2: void FUN_00106270(long param_1,undefined8 *param_2,long *param_3,uint param_4,int param_5)
3: 
4: {
5: undefined uVar1;
6: int iVar2;
7: uint uVar3;
8: long lVar4;
9: long lVar5;
10: undefined8 *puVar6;
11: undefined *puVar7;
12: ulong uVar8;
13: 
14: iVar2 = *(int *)(param_1 + 0x38);
15: uVar3 = *(uint *)(param_1 + 0x30);
16: do {
17: param_5 = param_5 + -1;
18: puVar6 = param_2;
19: if (param_5 < 0) {
20: return;
21: }
22: while( true ) {
23: uVar8 = (ulong)param_4;
24: param_2 = puVar6 + 1;
25: param_4 = param_4 + 1;
26: puVar7 = (undefined *)*puVar6;
27: lVar4 = *(long *)(*param_3 + uVar8 * 8);
28: lVar5 = 0;
29: if (uVar3 == 0) break;
30: do {
31: uVar1 = *puVar7;
32: puVar7 = puVar7 + iVar2;
33: *(undefined *)(lVar4 + lVar5) = uVar1;
34: lVar5 = lVar5 + 1;
35: } while ((uint)lVar5 < uVar3);
36: param_5 = param_5 + -1;
37: puVar6 = param_2;
38: if (param_5 < 0) {
39: return;
40: }
41: }
42: } while( true );
43: }
44: 
