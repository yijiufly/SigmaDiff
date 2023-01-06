1: 
2: /* WARNING: Switch with 1 destination removed at 0x001683bf */
3: /* WARNING: Switch with 1 destination removed at 0x001683e8 */
4: 
5: undefined  [16] FUN_00168380(long param_1,long *param_2,ulong param_3,long param_4)
6: 
7: {
8: uint uVar1;
9: ulong uVar2;
10: long lStack72;
11: long lStack64;
12: long lStack56;
13: 
14: switch(*(undefined4 *)(param_1 + 0x40)) {
15: case 6:
16: break;
17: case 7:
18: case 0xc:
19: break;
20: case 8:
21: uVar1 = *(uint *)(param_1 + 0x88);
22: goto joined_r0x001683e3;
23: case 9:
24: case 0xd:
25: break;
26: case 10:
27: case 0xe:
28: break;
29: case 0xb:
30: case 0xf:
31: }
32: uVar1 = *(uint *)(param_1 + 0x88);
33: joined_r0x001683e3:
34: uVar2 = (ulong)uVar1;
35: if ((DAT_003a61e0 & 0x80) == 0) {
36: param_3 = param_3 & 0xffffffff;
37: lStack64 = param_2[1];
38: lStack56 = param_2[2];
39: lStack72 = *param_2 + param_3 * 8;
40: FUN_0015b340(uVar2,&lStack72,param_3,param_4);
41: lStack72 = lStack72 + 8;
42: FUN_0015b340(uVar2,&lStack72,param_3,param_4 + 8);
43: return CONCAT88(lStack56,uVar2);
44: }
45: param_3 = param_3 & 0xffffffff;
46: lStack64 = param_2[1];
47: lStack56 = param_2[2];
48: lStack72 = *param_2 + param_3 * 8;
49: FUN_00164e40(uVar2,&lStack72,param_3,param_4);
50: lStack72 = lStack72 + 8;
51: FUN_00164e40(uVar2,&lStack72,param_3,param_4 + 8);
52: return CONCAT88(lStack56,uVar2);
53: }
54: 
