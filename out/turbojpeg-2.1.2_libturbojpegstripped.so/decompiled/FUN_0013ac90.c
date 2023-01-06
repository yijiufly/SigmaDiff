1: 
2: void FUN_0013ac90(long param_1,undefined8 param_2,int *param_3,undefined8 param_4,long param_5,
3: uint *param_6,int param_7)
4: 
5: {
6: undefined8 *puVar1;
7: uint uVar2;
8: int iVar3;
9: long lVar4;
10: uint uVar5;
11: uint uVar6;
12: long in_FS_OFFSET;
13: undefined8 uStack72;
14: undefined8 uStack64;
15: long lStack48;
16: 
17: lVar4 = *(long *)(param_1 + 0x260);
18: uVar2 = *param_6;
19: lStack48 = *(long *)(in_FS_OFFSET + 0x28);
20: puVar1 = (undefined8 *)(param_5 + (ulong)uVar2 * 8);
21: if (*(int *)(lVar4 + 0x48) != 0) {
22: iVar3 = *(int *)(lVar4 + 0x4c);
23: if (*(int *)(param_1 + 0x40) == 0x10) {
24: iVar3 = *(int *)(param_1 + 0x88) * 2;
25: }
26: uVar5 = 1;
27: FUN_00148a00(lVar4 + 0x40,0,puVar1,0,1,iVar3);
28: *(undefined4 *)(lVar4 + 0x48) = 0;
29: goto LAB_0013acf5;
30: }
31: uVar5 = *(uint *)(lVar4 + 0x50);
32: uStack72 = *puVar1;
33: uVar6 = param_7 - uVar2;
34: if (uVar5 < 2) {
35: if (uVar6 < uVar5) goto LAB_0013ad3e;
36: LAB_0013ad42:
37: uStack64 = *(undefined8 *)(lVar4 + 0x40);
38: *(undefined4 *)(lVar4 + 0x48) = 1;
39: }
40: else {
41: if (uVar6 < 2) {
42: LAB_0013ad3e:
43: uVar5 = uVar6;
44: goto LAB_0013ad42;
45: }
46: uVar5 = 2;
47: uStack64 = *(undefined8 *)(param_5 + (ulong)(uVar2 + 1) * 8);
48: }
49: (**(code **)(lVar4 + 0x18))(param_1,param_2,*param_3,&uStack72);
50: LAB_0013acf5:
51: *param_6 = *param_6 + uVar5;
52: *(int *)(lVar4 + 0x50) = *(int *)(lVar4 + 0x50) - uVar5;
53: if (*(int *)(lVar4 + 0x48) == 0) {
54: *param_3 = *param_3 + 1;
55: }
56: if (lStack48 != *(long *)(in_FS_OFFSET + 0x28)) {
57: /* WARNING: Subroutine does not return */
58: __stack_chk_fail();
59: }
60: return;
61: }
62: 
