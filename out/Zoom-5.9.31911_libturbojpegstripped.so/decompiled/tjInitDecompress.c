1: 
2: /* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
3: 
4: undefined8 tjInitDecompress(void)
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
15: if (puVar1 != (undefined8 *)0x0) {
16: lVar3 = 0xdb;
17: puVar4 = puVar1;
18: while (lVar3 != 0) {
19: lVar3 = lVar3 + -1;
20: *puVar4 = 0;
21: puVar4 = puVar4 + (ulong)bVar5 * -2 + 1;
22: }
23: puVar1[0xc1] = 0x726f727265206f4e;
24: uVar2 = FUN_00141e80(puVar1);
25: return uVar2;
26: }
27: s_No_error_003a6000._0_8_ = 0x654474696e496a74;
28: ram0x003a6008 = 0x73736572706d6f63;
29: _DAT_003a6010 = 0x6f6d654d203a2928;
30: _DAT_003a6018 = 0x636f6c6c61207972;
31: _DAT_003a6020 = 0x6166206e6f697461;
32: _DAT_003a6028 = 0x72756c69;
33: _DAT_003a602c = 0x65;
34: return 0;
35: }
36: 
