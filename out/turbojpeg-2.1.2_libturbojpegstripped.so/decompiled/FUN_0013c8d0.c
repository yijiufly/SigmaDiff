1: 
2: void FUN_0013c8d0(long param_1,long param_2,int *param_3,undefined8 param_4,long param_5,
3: uint *param_6,int param_7)
4: 
5: {
6: long lVar1;
7: uint uVar2;
8: int iVar3;
9: int iVar4;
10: long lVar5;
11: long lVar6;
12: 
13: lVar1 = *(long *)(param_1 + 0x260);
14: iVar4 = *(int *)(param_1 + 0x19c);
15: iVar3 = *(int *)(lVar1 + 0xb8);
16: if (iVar4 <= iVar3) {
17: if (0 < *(int *)(param_1 + 0x38)) {
18: lVar5 = 1;
19: lVar6 = *(long *)(param_1 + 0x130);
20: do {
21: (**(code **)(lVar1 + 0x60 + lVar5 * 8))
22: (param_1,lVar6,
23: *(long *)(param_2 + -8 + lVar5 * 8) +
24: (ulong)(uint)(*param_3 * *(int *)(lVar1 + 0xbc + lVar5 * 4)) * 8);
25: iVar4 = (int)lVar5;
26: lVar5 = lVar5 + 1;
27: lVar6 = lVar6 + 0x60;
28: } while (*(int *)(param_1 + 0x38) != iVar4 && iVar4 <= *(int *)(param_1 + 0x38));
29: iVar4 = *(int *)(param_1 + 0x19c);
30: }
31: *(undefined4 *)(lVar1 + 0xb8) = 0;
32: iVar3 = 0;
33: }
34: uVar2 = param_7 - *param_6;
35: if (*(uint *)(lVar1 + 0xbc) < uVar2 || *(uint *)(lVar1 + 0xbc) == uVar2) {
36: uVar2 = *(uint *)(lVar1 + 0xbc);
37: }
38: if ((uint)(iVar4 - iVar3) < uVar2) {
39: uVar2 = iVar4 - iVar3;
40: }
41: (**(code **)(*(long *)(param_1 + 0x268) + 8))
42: (param_1,lVar1 + 0x18,iVar3,param_5 + (ulong)*param_6 * 8,uVar2);
43: *param_6 = *param_6 + uVar2;
44: *(int *)(lVar1 + 0xbc) = *(int *)(lVar1 + 0xbc) - uVar2;
45: iVar3 = uVar2 + *(int *)(lVar1 + 0xb8);
46: iVar4 = *(int *)(param_1 + 0x19c);
47: *(int *)(lVar1 + 0xb8) = iVar3;
48: if (iVar4 <= iVar3) {
49: *param_3 = *param_3 + 1;
50: }
51: return;
52: }
53: 
