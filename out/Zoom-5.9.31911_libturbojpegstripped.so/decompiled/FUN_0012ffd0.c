1: 
2: void FUN_0012ffd0(long param_1,undefined8 param_2,int *param_3,undefined8 param_4,long param_5,
3: uint *param_6,int param_7)
4: 
5: {
6: int iVar1;
7: uint uVar2;
8: long lVar3;
9: uint uVar4;
10: undefined8 uStack56;
11: undefined8 uStack48;
12: 
13: lVar3 = *(long *)(param_1 + 0x260);
14: if (*(int *)(lVar3 + 0x48) != 0) {
15: iVar1 = *(int *)(lVar3 + 0x4c);
16: if (*(int *)(param_1 + 0x40) == 0x10) {
17: iVar1 = *(int *)(param_1 + 0x88) * 2;
18: }
19: uVar4 = 1;
20: FUN_0013be50(lVar3 + 0x40,0,param_5 + (ulong)*param_6 * 8,0,1,iVar1);
21: *(undefined4 *)(lVar3 + 0x48) = 0;
22: goto LAB_00130023;
23: }
24: uVar4 = *(uint *)(lVar3 + 0x50);
25: if (1 < uVar4) {
26: uVar4 = 2;
27: }
28: uVar2 = *param_6;
29: if (param_7 - uVar2 < uVar4) {
30: uStack56 = *(undefined8 *)(param_5 + (ulong)uVar2 * 8);
31: uVar4 = param_7 - uVar2;
32: LAB_00130098:
33: *(undefined4 *)(lVar3 + 0x48) = 1;
34: uStack48 = *(undefined8 *)(lVar3 + 0x40);
35: }
36: else {
37: uStack56 = *(undefined8 *)(param_5 + (ulong)uVar2 * 8);
38: if (uVar4 != 2) goto LAB_00130098;
39: uStack48 = *(undefined8 *)(param_5 + (ulong)(uVar2 + 1) * 8);
40: }
41: (**(code **)(lVar3 + 0x18))(param_1,param_2,*param_3,&uStack56);
42: LAB_00130023:
43: *param_6 = *param_6 + uVar4;
44: *(int *)(lVar3 + 0x50) = *(int *)(lVar3 + 0x50) - uVar4;
45: if (*(int *)(lVar3 + 0x48) == 0) {
46: *param_3 = *param_3 + 1;
47: }
48: return;
49: }
50: 
