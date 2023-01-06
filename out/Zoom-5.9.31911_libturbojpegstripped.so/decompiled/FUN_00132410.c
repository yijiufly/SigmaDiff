1: 
2: void FUN_00132410(long param_1,long param_2,byte **param_3,ulong **param_4)
3: 
4: {
5: byte bVar1;
6: byte bVar2;
7: void **ppvVar3;
8: void *pvVar4;
9: void *pvVar5;
10: int iVar6;
11: byte *pbVar7;
12: void **ppvStack104;
13: byte **ppbStack96;
14: 
15: ppvVar3 = (void **)*param_4;
16: bVar1 = *(byte *)(*(long *)(param_1 + 0x260) + 0xe8 + (long)*(int *)(param_2 + 4));
17: bVar2 = *(byte *)(*(long *)(param_1 + 0x260) + 0xf2 + (long)*(int *)(param_2 + 4));
18: if (0 < *(int *)(param_1 + 0x19c)) {
19: iVar6 = 0;
20: ppvStack104 = ppvVar3;
21: ppbStack96 = param_3;
22: do {
23: pvVar4 = *ppvStack104;
24: pvVar5 = (void *)((ulong)*(uint *)(param_1 + 0x88) + (long)pvVar4);
25: if (pvVar4 < pvVar5) {
26: pbVar7 = *ppbStack96;
27: if (bVar1 == 0) {
28: do {
29: if (pvVar5 <= pvVar4) break;
30: } while (pvVar4 < pvVar5);
31: }
32: else {
33: do {
34: pvVar4 = memset(pvVar4,(uint)*pbVar7,(ulong)bVar1);
35: pvVar4 = (void *)((long)pvVar4 + (ulong)(bVar1 - 1) + 1);
36: pbVar7 = pbVar7 + 1;
37: } while (pvVar4 < pvVar5);
38: }
39: }
40: if (1 < bVar2) {
41: FUN_0013be50(ppvVar3,iVar6,ppvVar3,iVar6 + 1,bVar2 - 1,*(undefined4 *)(param_1 + 0x88));
42: }
43: iVar6 = iVar6 + (uint)bVar2;
44: ppbStack96 = ppbStack96 + 1;
45: ppvStack104 = ppvStack104 + bVar2;
46: } while (*(int *)(param_1 + 0x19c) != iVar6 && iVar6 <= *(int *)(param_1 + 0x19c));
47: }
48: return;
49: }
50: 
