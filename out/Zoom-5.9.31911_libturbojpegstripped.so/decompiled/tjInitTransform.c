1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8 tjInitTransform(void)
5: 
6: {
7: undefined8 *puVar1;
8: undefined8 uVar2;
9: long lVar3;
10: undefined8 *puVar4;
11: byte bVar5;
12: 
13: bVar5 = 0;
14: puVar1 = (undefined8 *)malloc(0x6d8);
15: if (puVar1 == (undefined8 *)0x0) {
16: _DAT_003a6028 = 0x6572756c;
17: DAT_003a602c = 0;
18: s_No_error_003a6000._0_8_ = 0x725474696e496a74;
19: ram0x003a6008 = 0x286d726f66736e61;
20: _DAT_003a6010 = 0x726f6d654d203a29;
21: _DAT_003a6018 = 0x61636f6c6c612079;
22: _DAT_003a6020 = 0x696166206e6f6974;
23: }
24: else {
25: lVar3 = 0xdb;
26: puVar4 = puVar1;
27: while (lVar3 != 0) {
28: lVar3 = lVar3 + -1;
29: *puVar4 = 0;
30: puVar4 = puVar4 + (ulong)bVar5 * -2 + 1;
31: }
32: puVar1[0xc1] = 0x726f727265206f4e;
33: lVar3 = FUN_00141a60(puVar1);
34: if (lVar3 != 0) {
35: uVar2 = FUN_00141e80(puVar1);
36: return uVar2;
37: }
38: }
39: return 0;
40: }
41: 
