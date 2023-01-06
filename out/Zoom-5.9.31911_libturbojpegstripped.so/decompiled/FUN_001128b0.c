1: 
2: void FUN_001128b0(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: code **ppcVar3;
7: code *pcVar4;
8: long lVar5;
9: code *pcVar6;
10: int iVar7;
11: int iVar2;
12: 
13: ppcVar3 = (code **)(**(code **)param_1[1])(param_1,1,0x70);
14: iVar7 = *(int *)(param_1 + 0x20);
15: param_1[0x37] = (code *)ppcVar3;
16: *ppcVar3 = FUN_00112750;
17: if (iVar7 == 0) {
18: if (param_2 != 0) {
19: ppcVar3 = (code **)*param_1;
20: *(undefined4 *)(ppcVar3 + 5) = 4;
21: /* WARNING: Could not recover jumptable at 0x00112962. Too many branches */
22: /* WARNING: Treating indirect jump as call */
23: (**ppcVar3)(param_1);
24: return;
25: }
26: if (0 < *(int *)((long)param_1 + 0x4c)) {
27: iVar7 = 0;
28: pcVar6 = param_1[0xb];
29: do {
30: pcVar4 = (code *)(**(code **)(param_1[1] + 0x10))
31: (param_1,1,*(int *)(pcVar6 + 0x1c) * 8,*(int *)(pcVar6 + 0xc) * 8
32: );
33: lVar5 = (long)iVar7;
34: iVar7 = iVar7 + 1;
35: iVar1 = *(int *)((long)param_1 + 0x4c);
36: iVar2 = *(int *)((long)param_1 + 0x4c);
37: ppcVar3[lVar5 + 4] = pcVar4;
38: pcVar6 = pcVar6 + 0x60;
39: } while (iVar2 != iVar7 && iVar7 <= iVar1);
40: }
41: }
42: return;
43: }
44: 
