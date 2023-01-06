1: 
2: void FUN_00131a20(long param_1,long param_2,int *param_3,undefined8 param_4,long param_5,
3: uint *param_6,int param_7)
4: 
5: {
6: long lVar1;
7: int iVar2;
8: uint uVar3;
9: int iVar4;
10: long lVar5;
11: long lVar6;
12: long lVar7;
13: long lStack64;
14: 
15: lVar1 = *(long *)(param_1 + 0x260);
16: iVar2 = *(int *)(param_1 + 0x19c);
17: iVar4 = *(int *)(lVar1 + 0xb8);
18: if (iVar2 <= iVar4) {
19: lVar6 = lVar1 + 0x18;
20: lVar5 = 0;
21: lVar7 = *(long *)(param_1 + 0x130);
22: if (0 < *(int *)(param_1 + 0x38)) {
23: do {
24: (**(code **)(lVar6 + 0x50))
25: (param_1,lVar7,
26: *(long *)(param_2 + lVar5 * 8) +
27: (ulong)(uint)(*(int *)(lVar1 + 0xc0 + lVar5 * 4) * *param_3) * 8);
28: iVar2 = (int)lVar5 + 1;
29: lVar6 = lVar6 + 8;
30: lVar5 = lVar5 + 1;
31: lVar7 = lVar7 + 0x60;
32: } while (*(int *)(param_1 + 0x38) != iVar2 && iVar2 <= *(int *)(param_1 + 0x38));
33: iVar2 = *(int *)(param_1 + 0x19c);
34: }
35: *(undefined4 *)(lVar1 + 0xb8) = 0;
36: iVar4 = 0;
37: }
38: lStack64 = lVar1 + 0x18;
39: uVar3 = param_7 - *param_6;
40: if (*(uint *)(lVar1 + 0xbc) < uVar3) {
41: uVar3 = *(uint *)(lVar1 + 0xbc);
42: }
43: if ((uint)(iVar2 - iVar4) < uVar3) {
44: uVar3 = iVar2 - iVar4;
45: }
46: (**(code **)(*(long *)(param_1 + 0x268) + 8))
47: (param_1,lStack64,iVar4,param_5 + (ulong)*param_6 * 8,uVar3);
48: *param_6 = *param_6 + uVar3;
49: *(int *)(lVar1 + 0xbc) = *(int *)(lVar1 + 0xbc) - uVar3;
50: iVar4 = uVar3 + *(int *)(lVar1 + 0xb8);
51: iVar2 = *(int *)(param_1 + 0x19c);
52: *(int *)(lVar1 + 0xb8) = iVar4;
53: if (iVar2 <= iVar4) {
54: *param_3 = *param_3 + 1;
55: }
56: return;
57: }
58: 
