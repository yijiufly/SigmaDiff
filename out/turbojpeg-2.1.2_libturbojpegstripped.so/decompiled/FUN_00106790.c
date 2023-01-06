1: 
2: void FUN_00106790(long param_1,undefined8 *param_2,long *param_3,uint param_4,int param_5)
3: 
4: {
5: undefined uVar1;
6: int iVar2;
7: int iVar3;
8: undefined *puVar4;
9: undefined *puVar5;
10: undefined *puVar6;
11: undefined8 *puVar7;
12: undefined *puVar8;
13: ulong uVar9;
14: 
15: iVar2 = *(int *)(param_1 + 0x30);
16: iVar3 = *(int *)(param_1 + 0x38);
17: do {
18: param_5 = param_5 + -1;
19: puVar7 = param_2;
20: if (param_5 < 0) {
21: return;
22: }
23: while( true ) {
24: param_2 = puVar7 + 1;
25: uVar9 = (ulong)param_4;
26: param_4 = param_4 + 1;
27: puVar8 = (undefined *)*puVar7;
28: puVar4 = *(undefined **)(*param_3 + uVar9 * 8);
29: if (iVar2 == 0) break;
30: puVar5 = puVar4;
31: do {
32: uVar1 = *puVar8;
33: puVar6 = puVar5 + 1;
34: puVar8 = puVar8 + iVar3;
35: *puVar5 = uVar1;
36: puVar5 = puVar6;
37: } while (puVar4 + (ulong)(iVar2 - 1) + 1 != puVar6);
38: param_5 = param_5 + -1;
39: puVar7 = param_2;
40: if (param_5 < 0) {
41: return;
42: }
43: }
44: } while( true );
45: }
46: 
