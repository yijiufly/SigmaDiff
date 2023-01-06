1: 
2: void FUN_0011c250(code **param_1,int param_2)
3: 
4: {
5: int iVar1;
6: code **ppcVar2;
7: code *pcVar3;
8: code *pcVar4;
9: long lVar5;
10: 
11: ppcVar2 = (code **)(**(code **)param_1[1])(param_1,1,0x70);
12: iVar1 = *(int *)(param_1 + 0x20);
13: param_1[0x37] = (code *)ppcVar2;
14: *ppcVar2 = FUN_0011c0e0;
15: if (iVar1 == 0) {
16: if (param_2 != 0) {
17: ppcVar2 = (code **)*param_1;
18: *(undefined4 *)(ppcVar2 + 5) = 4;
19: /* WARNING: Could not recover jumptable at 0x0011c2ae. Too many branches */
20: /* WARNING: Treating indirect jump as call */
21: (**ppcVar2)(param_1);
22: return;
23: }
24: if (0 < *(int *)((long)param_1 + 0x4c)) {
25: lVar5 = 1;
26: pcVar4 = param_1[0xb];
27: do {
28: pcVar3 = (code *)(**(code **)(param_1[1] + 0x10))
29: (param_1,1,*(int *)(pcVar4 + 0x1c) * 8,*(int *)(pcVar4 + 0xc) * 8
30: );
31: ppcVar2[lVar5 + 3] = pcVar3;
32: iVar1 = (int)lVar5;
33: lVar5 = lVar5 + 1;
34: pcVar4 = pcVar4 + 0x60;
35: } while (*(int *)((long)param_1 + 0x4c) != iVar1 && iVar1 <= *(int *)((long)param_1 + 0x4c));
36: }
37: }
38: return;
39: }
40: 
