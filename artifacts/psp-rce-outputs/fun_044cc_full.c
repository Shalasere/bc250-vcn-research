
int FUN_000044cc(int param_1,uint *param_2)

{
  char *pcVar1;
  undefined4 *puVar2;
  uint *puVar3;
  undefined2 uVar4;
  uint uVar5;
  uint *puVar6;
  undefined1 *puVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  undefined4 *puVar11;
  uint *puVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  bool bVar16;
  bool bVar17;
  undefined1 uVar18;
  uint local_40;
  uint *local_3c;
  uint local_38;
  undefined4 local_34;
  undefined4 local_30;
  int local_2c;
  
  puVar6 = DAT_000048e4;
  pcVar1 = DAT_000048e0;
  iVar13 = 0;
  iVar9 = 0;
  if (((param_1 == 0x20) || (param_1 == 0x66)) && (*DAT_000048dc != 1)) {
    iVar9 = 4;
  }
  if (iVar9 != 0) goto LAB_00004638;
  puVar12 = DAT_000048e4 + 4;
  *(int *)(DAT_000048e0 + 4) = param_1;
  uVar10 = param_2[1];
  uVar14 = param_2[2];
  uVar15 = param_2[3];
  *puVar6 = *param_2;
  puVar6[1] = uVar10;
  puVar6[2] = uVar14;
  puVar11 = (undefined4 *)&DAT_00000001;
  puVar6[3] = uVar15;
  puVar3 = DAT_00004e4c;
  if (param_1 == 0x44) {
LAB_00004cc8:
    if (*param_2 == 3) {
      puVar6[4] = 0;
      puVar6[5] = 0;
      puVar6[6] = 0;
      iVar8 = FUN_000061e4(param_2[2],param_2[1],param_2[3]);
      if (iVar8 != 0) {
        *puVar12 = param_2[1];
        puVar6[5] = param_2[2];
        puVar6[6] = param_2[3];
        goto LAB_00004638;
      }
    }
    else {
      if (*param_2 != 4) {
LAB_00004d16:
        iVar9 = 0x15;
        goto LAB_00004638;
      }
      if (param_2[3] == 0x10000000) {
        *DAT_00004e4c = param_2[1];
        puVar3[1] = param_2[2];
        puVar3[2] = 0x10000000;
        goto LAB_00004638;
      }
    }
    goto LAB_00004fee;
  }
  if (0x44 < param_1) {
    if (param_1 == 0xa1) goto LAB_00004bb4;
    if (param_1 < 0xa2) {
      iVar8 = *DAT_000048ec;
      if (param_1 == 0x5d) {
LAB_00004e60:
        if (*param_2 < 2) {
          uVar18 = *param_2 != 0;
          puVar7 = DAT_00005018;
          goto LAB_00004e6c;
        }
      }
      else {
        if (param_1 < 0x5e) {
          if (param_1 == 0x51) {
            iVar9 = FUN_00008308(*param_2,param_2[1]);
            goto LAB_00004638;
          }
          if (0x51 < param_1) {
            if (param_1 == 0x5a) goto LAB_00004db8;
            if (0x5a < param_1) {
              bVar16 = param_1 == 0x5b;
              goto LAB_000045ac;
            }
            if (param_1 == 0x52) {
              FUN_0000312c(iVar8);
              goto LAB_00004638;
            }
            if (param_1 == 0x53) goto LAB_00004d9e;
            goto switchD_00004522_caseD_0;
          }
          if (param_1 == 0x4e) {
            if (*DAT_00004e54 == 0x23) goto LAB_00004638;
            if (param_2[1] == 0) {
              iVar9 = FUN_000079d0(*param_2);
              goto LAB_00004638;
            }
            goto LAB_00004fee;
          }
          if (param_1 < 0x4f) {
            if (param_1 == 0x45) {
              iVar9 = FUN_00004480(param_2[1],4);
              if (((iVar9 != 0) || (iVar9 = FUN_00004480(param_2[2],4), iVar9 != 0)) ||
                 (iVar9 = FUN_00004480(param_2[3],4), iVar9 != 0)) goto LAB_00004638;
              if (*param_2 == 0) {
                if (puVar6[6] == 0) {
                  iVar9 = 0x4a;
                }
                else {
                  uVar14 = puVar6[5];
                  uVar10 = *puVar12;
                  *(uint *)param_2[1] = uVar10 - 1;
                  *(uint *)param_2[2] = uVar14 + (uVar10 != 0);
                  *(undefined4 *)param_2[3] = 0;
                }
                goto LAB_00004638;
              }
              goto LAB_00004d16;
            }
            if (param_1 == 0x4d) goto switchD_00004522_caseD_2d;
          }
          else {
            puVar7 = DAT_00004e58;
            if (param_1 == 0x4f) goto LAB_00004d92;
            if (param_1 == 0x50) {
              uVar10 = (*param_2 & 0xfffff) + param_2[1];
              if ((uVar10 & 0xfffff) != 0) {
                uVar10 = (uVar10 & 0xfff00000) + 0x100000;
              }
              if (param_2[1] <= uVar10) {
                iVar13 = FUN_00007910(*param_2);
              }
              goto LAB_00004638;
            }
          }
          goto switchD_00004522_caseD_0;
        }
        if (param_1 == 0x65) {
          iVar9 = FUN_00004480(param_2[1],8);
          if (iVar9 == 0) {
            iVar9 = FUN_00007afa(*param_2,param_2[1],param_2[2],param_2[3]);
          }
          goto LAB_00004638;
        }
        if (param_1 < 0x66) {
          switch(param_1) {
          case 0x5f:
            goto LAB_00004f9e;
          case 0x60:
            FUN_00007cec();
            goto LAB_00004638;
          case 0x61:
            uVar10 = *param_2;
            puVar6 = DAT_00005028;
            goto LAB_00004afc;
          case 0x62:
            if ((iVar8 == 1) || (iVar8 == 2)) {
              iVar9 = FUN_00003214(iVar8);
              goto LAB_00004638;
            }
            break;
          case 99:
LAB_00004f5e:
            puVar11 = (undefined4 *)*param_2;
            iVar9 = FUN_00004480(puVar11,0x20);
            if ((iVar9 == 0) && (iVar9 = FUN_00004480(puVar11[7],4), iVar9 == 0)) {
              local_40 = puVar11[1];
              local_3c = (uint *)puVar11[2];
              local_38 = puVar11[3];
              local_34 = puVar11[4];
              local_30 = puVar11[5];
              local_2c = puVar11[6];
              iVar9 = FUN_00007f20(*puVar11,&local_40,puVar11[7]);
            }
            goto LAB_00004638;
          default:
            goto switchD_00004522_caseD_0;
          }
        }
        else {
          if (param_1 == 0x66) goto LAB_00004638;
          if (param_1 == 0x67) {
            iVar9 = FUN_00004480(param_2[1],4);
            if (iVar9 != 0) goto LAB_00004638;
          }
          else {
            if (param_1 != 0x69) {
              if (param_1 == 0xa0) goto LAB_00004f5e;
              goto switchD_00004522_caseD_0;
            }
            if (*param_2 < 2) {
              uVar18 = *param_2 != 0;
              puVar7 = DAT_0000502c;
              goto LAB_00004e6c;
            }
          }
        }
      }
      goto LAB_00004fee;
    }
    bVar16 = true;
    if (param_1 == 0xaf) {
LAB_000045ac:
      if (bVar16) {
        iVar9 = FUN_00004480(*param_2,4);
        if (iVar9 == 0) {
          iVar9 = FUN_00006b82(*param_2);
        }
        goto LAB_00004638;
      }
      if (param_1 == 0x5c) {
LAB_00004e2c:
        iVar9 = FUN_000080ec(*param_2,param_2[1],param_2[2],param_2[3]);
        goto LAB_00004638;
      }
      goto switchD_00004522_caseD_0;
    }
    if (param_1 < 0xb0) {
      switch(param_1) {
      case 0xa2:
        goto LAB_00004bbe;
      case 0xa3:
        goto LAB_00004a38;
      case 0xa4:
        goto LAB_00004abe;
      case 0xa5:
        goto LAB_00004be0;
      case 0xa6:
        goto LAB_00004c18;
      case 0xa7:
        goto LAB_00004c42;
      case 0xa8:
        iVar9 = FUN_00004480(*param_2,8);
        goto LAB_00004638;
      case 0xa9:
        iVar9 = 0;
        if (*param_2 == 1) {
          pcVar1[8] = '\0';
          pcVar1[9] = '\0';
          pcVar1[10] = '\0';
          pcVar1[0xb] = '\0';
          goto LAB_00004638;
        }
        break;
      default:
        goto switchD_00004522_caseD_0;
      case 0xae:
LAB_00004db8:
        uVar14 = *param_2;
        uVar10 = 0xff;
        iVar8 = 2;
        if (((uVar14 < 3) || (uVar14 == 0xff)) && (uVar15 = param_2[1], uVar15 < 2)) {
          if (uVar14 == 0) {
            uVar10 = 0;
          }
          else if (uVar14 == 1) {
            uVar10 = 1;
          }
          else if (uVar14 == 2) {
            uVar10 = 2;
          }
          else if (uVar14 != 0xff) {
            iVar9 = 4;
          }
          if (uVar15 == 1) {
            iVar8 = 1;
          }
          else if (uVar15 == 0) {
            iVar8 = 0;
          }
          *DAT_00004e5c = uVar10 | iVar8 << 8 | *DAT_00004e5c & 0xffff0000;
          goto LAB_00004638;
        }
      }
      goto LAB_00004fee;
    }
    if (param_1 == 0xf0) goto LAB_00004638;
    if (0xf0 < param_1) {
      if (param_1 == 0xf1) {
        uVar14 = *param_2;
        uVar10 = param_2[1];
        uVar15 = param_2[3];
        iVar9 = FUN_00004480(uVar15,0x10);
        if (iVar9 != 0) goto LAB_00004638;
        if ((uVar14 != 0 || uVar10 != 0) && (uVar15 != 0)) {
          iVar8 = FUN_00003600(uVar14,uVar10);
          if (iVar8 == 0) {
            iVar9 = 7;
          }
          else {
            local_40 = param_2[2];
            local_3c = (uint *)uVar15;
            iVar9 = FUN_00001720(DAT_0000501c,2,0x10,iVar8);
            FUN_00005094(iVar8);
          }
          goto LAB_00004638;
        }
      }
      else if (param_1 == 0xf2) {
        if ((uint *)*param_2 + -0xc00000 < DAT_000048f0) {
          *(uint *)*param_2 = param_2[1];
          goto LAB_00004638;
        }
      }
      else {
        if (param_1 != 0xf3) {
          if (param_1 == 0xf4) {
            iVar9 = FUN_00004480(*param_2,0x10000);
            if (iVar9 == 0) {
              iVar9 = FUN_000030e0(*param_2);
            }
            goto LAB_00004638;
          }
          goto switchD_00004522_caseD_0;
        }
        if ((uint *)(*param_2 + 0xfd000000) < DAT_000048f0) {
          iVar9 = FUN_00004480(param_2[1],4);
          if (iVar9 != 0) goto LAB_00004638;
          uVar10 = *(uint *)*param_2;
          goto LAB_00004f0e;
        }
      }
LAB_00004ec4:
      iVar9 = 10;
      goto LAB_00004638;
    }
    if (param_1 == 0xb3) {
LAB_00004f9e:
      uVar18 = *param_2 == 1;
      puVar7 = DAT_00005024;
      if (*param_2 < 2) goto LAB_00004e6c;
      goto LAB_00004fee;
    }
    if (param_1 < 0xb4) {
      if (param_1 == 0xb0) goto LAB_00004e2c;
      if (param_1 == 0xb1) goto LAB_00004e60;
    }
    else {
      if (param_1 == 0xde) {
        param_2 = (uint *)*param_2;
        iVar9 = FUN_00004480(param_2,0x20);
        bVar16 = false;
        if (iVar9 != 0) {
LAB_00004992:
          bVar17 = false;
          if (bVar16) {
            iVar9 = FUN_000022a0(*param_2,3,0);
            goto LAB_00004638;
          }
          goto LAB_000048a6;
        }
        iVar9 = FUN_00004480(param_2[6],4);
        bVar16 = iVar9 == 0;
        if (!bVar16) goto LAB_00004992;
        iVar9 = FUN_00004480(param_2[4],8);
        bVar16 = iVar9 == 0;
        if (!bVar16) {
LAB_000049ac:
          if (!bVar16) goto LAB_000048be;
          iVar9 = FUN_00004480(puVar11[4],4);
          bVar16 = iVar9 == 0;
LAB_000049b8:
          bVar17 = false;
          if (bVar16) {
            iVar9 = FUN_00004480(puVar11[2],8);
            bVar16 = iVar9 == 0;
            goto LAB_000049c4;
          }
          goto LAB_000048ca;
        }
        iVar9 = FUN_00004480(param_2[5],4);
        bVar16 = iVar9 == 0;
        if (!bVar16) goto LAB_000049ac;
        iVar9 = FUN_00004480(param_2[3],4);
        bVar16 = iVar9 == 0;
        if (!bVar16) goto LAB_000049b8;
        iVar9 = FUN_00004480(param_2[1],4);
        bVar16 = false;
        if (iVar9 == 0) {
          iVar9 = FUN_000053c4(param_2);
          goto LAB_00004638;
        }
LAB_000049c4:
        bVar17 = false;
        if (bVar16) {
          iVar9 = FUN_00004480(puVar11[3],4);
          bVar16 = false;
          if (iVar9 == 0) {
            iVar9 = FUN_00004480(puVar11[1],4);
            bVar17 = iVar9 == 0;
            goto LAB_000049dc;
          }
          goto LAB_0000490e;
        }
        goto LAB_000048d6;
      }
      if (param_1 == 0xea) {
        iVar9 = FUN_00004480(*param_2,8);
        if ((iVar9 == 0) && (iVar9 = FUN_00004480(param_2[1],4), iVar9 == 0)) {
          iVar9 = FUN_00006b94(*param_2,param_2[1]);
        }
        goto LAB_00004638;
      }
    }
switchD_00004522_caseD_0:
    iVar9 = 9;
    goto LAB_00004638;
  }
  switch(param_1) {
  default:
    goto switchD_00004522_caseD_0;
  case 1:
    iVar9 = FUN_00004480(param_2[2],4);
    if (iVar9 == 0) {
      iVar9 = FUN_0000373c(*param_2,param_2[1],param_2[2]);
    }
    break;
  case 2:
    uVar14 = *param_2;
    puVar11 = (undefined4 *)param_2[1];
    puVar6 = (uint *)param_2[2];
    uVar10 = *puVar6;
    iVar9 = FUN_00004480(puVar11,uVar10);
    if ((iVar9 != 0) || (iVar9 = FUN_00004480(puVar6,4), puVar2 = DAT_000048f4, iVar9 != 0)) break;
    if (uVar14 != 0xb) {
      if (((uVar14 == 0x95) || (uVar14 == 0x42)) || (uVar14 == 0x91)) {
        iVar9 = FUN_000073d0(uVar14,puVar11,uVar10);
        break;
      }
      local_38 = (uint)(uVar14 != 0x4f);
      local_3c = (undefined4 *)0x0;
LAB_00004cb2:
      local_40 = 2;
      FUN_000066a0(0,uVar14,puVar11,uVar10);
      FUN_0000120c(1,0,0,0xffffffff);
      break;
    }
    if (7 < uVar10) {
      *puVar11 = *DAT_000048f4;
      puVar11[1] = puVar2[1];
      break;
    }
    goto LAB_00004fee;
  case 3:
  case 4:
    if ((param_1 != 3) || (param_2[1] == 0)) {
      iVar13 = FUN_00003568(*param_2);
      break;
    }
    goto LAB_00004fee;
  case 5:
    iVar9 = FUN_0000511c(*param_2);
    break;
  case 6:
  case 0x1a:
    if (*DAT_000048e0 != '\0') {
      *DAT_000048e8 = 0;
    }
    break;
  case 7:
    iVar13 = FUN_00003600(*param_2,param_2[1]);
    break;
  case 8:
    iVar9 = FUN_00005094(*param_2);
    break;
  case 9:
    iVar9 = FUN_00004480(param_2[2],param_2[3]);
    bVar17 = iVar9 == 0;
    goto LAB_00004842;
  case 10:
    if (DAT_000048f8 == *param_2 && param_2[1] == 0xfffd) {
      iVar9 = FUN_00005af0(*param_2,param_2[1],param_2[2],param_2[3]);
    }
    else {
      iVar9 = FUN_00005a8c();
    }
    break;
  case 0xb:
    iVar9 = FUN_00004480(param_2[2],0x20);
    bVar17 = iVar9 == 0;
    goto LAB_0000487c;
  case 0xc:
    puVar11 = (undefined4 *)*param_2;
    iVar9 = FUN_00004480(puVar11,0x18);
    bVar17 = iVar9 == 0;
LAB_000048a6:
    if ((!bVar17) || (iVar9 = FUN_00004480(*puVar11,puVar11[1]), iVar9 != 0)) break;
    iVar9 = FUN_00004480(puVar11[2],puVar11[3]);
    bVar16 = iVar9 == 0;
LAB_000048be:
    if (!bVar16) break;
    iVar9 = FUN_00004480(puVar11[4],puVar11[3]);
    bVar17 = iVar9 == 0;
LAB_000048ca:
    if (!bVar17) break;
    iVar9 = FUN_00004480(puVar11[5],puVar11[3]);
    bVar17 = iVar9 == 0;
LAB_000048d6:
    if (bVar17) {
      iVar9 = FUN_00005030(*param_2);
    }
    break;
  case 0xd:
    puVar11 = (undefined4 *)*param_2;
    iVar9 = FUN_00004480(puVar11,0x1c);
    bVar16 = iVar9 == 0;
    goto LAB_0000490e;
  case 0xe:
    puVar11 = (undefined4 *)*param_2;
    iVar9 = FUN_00004480(puVar11,0x20);
    bVar17 = false;
    if (iVar9 == 0) {
      iVar9 = FUN_00004480(puVar11[3],puVar11[5]);
      bVar16 = iVar9 == 0;
LAB_00004960:
      bVar17 = false;
      if (bVar16) {
        iVar9 = FUN_00004480(puVar11[6],puVar11[5]);
        bVar16 = iVar9 == 0;
        goto LAB_0000496c;
      }
    }
    goto LAB_0000487c;
  case 0xf:
    iVar9 = FUN_00004480(*param_2,0x20);
    bVar16 = iVar9 == 0;
    goto LAB_00004992;
  case 0x16:
    puVar11 = (undefined4 *)*param_2;
    iVar9 = FUN_00004480(puVar11,0x18);
    bVar16 = iVar9 == 0;
    goto LAB_000049ac;
  case 0x19:
    *pcVar1 = *param_2 != 0;
    break;
  case 0x1b:
    FUN_0000505c(*param_2);
    break;
  case 0x1c:
    iVar9 = FUN_00004480(*param_2,4);
    if (iVar9 != 0) break;
    uVar10 = *DAT_00004e3c;
    puVar6 = (uint *)*param_2;
    goto LAB_00004afc;
  case 0x1d:
    iVar9 = FUN_00004480(*param_2,0x20);
    if (iVar9 == 0) {
      local_40 = *param_2;
      iVar9 = FUN_0000196c(param_2[2],param_2[1],DAT_00005020,0x20);
    }
    break;
  case 0x1f:
    iVar9 = FUN_00004480(*param_2,0x38);
    if ((iVar9 == 0) && (iVar9 = FUN_00004480(param_2[1],param_2[2]), iVar9 == 0)) {
      iVar9 = FUN_00002b1c(*param_2,param_2[1],param_2[2]);
    }
    break;
  case 0x20:
    iVar9 = FUN_00004480(*param_2,0x38);
    if (iVar9 == 0) {
      iVar9 = FUN_00004388(*param_2);
    }
    break;
  case 0x21:
    iVar9 = FUN_00003ba4(*param_2,(short)param_2[1]);
    if (iVar9 != 0) break;
    goto LAB_00004b44;
  case 0x25:
LAB_00004b44:
    iVar13 = FUN_00003650(*param_2,param_2[1],param_2[2],0xc0000000);
    break;
  case 0x26:
    uVar10 = *param_2;
    iVar9 = FUN_00004480(uVar10,0x14);
    if ((iVar9 == 0) &&
       (iVar9 = FUN_00004480(*(undefined4 *)(uVar10 + 8),*(undefined4 *)(uVar10 + 0xc)), iVar9 == 0)
       ) {
      iVar9 = FUN_00003dcc(uVar10);
    }
    break;
  case 0x27:
    uVar10 = *param_2;
    iVar9 = FUN_00004480(uVar10,0x14);
    if ((iVar9 == 0) &&
       (iVar9 = FUN_00004480(*(undefined4 *)(uVar10 + 8),*(undefined4 *)(uVar10 + 0xc)), iVar9 == 0)
       ) {
      iVar9 = FUN_00005ab4(uVar10);
    }
    break;
  case 0x28:
    iVar9 = FUN_00004480(param_2[2],4);
    if (iVar9 == 0) {
      iVar9 = FUN_000042d4(*param_2,param_2[1],param_2[2]);
    }
    break;
  case 0x2a:
    goto LAB_00004cc8;
  case 0x2d:
  case 0x32:
switchD_00004522_caseD_2d:
    if (param_1 == 0x2d) {
      uVar15 = param_2[1];
      puVar11 = (undefined4 *)param_2[2];
      uVar14 = (uint)(byte)*param_2 | ((byte)param_2[3] & 0xf) << 0x14;
      uVar10 = 0xf000ff;
    }
    else {
      uVar15 = param_2[2];
      puVar11 = (undefined4 *)param_2[3];
      uVar14 = *param_2;
      uVar10 = param_2[1];
    }
    iVar9 = FUN_00004480(uVar15,*puVar11);
    if (iVar9 == 0) {
      uVar5 = uVar14 & 0xff;
      if (((uVar5 == 0x60) || (uVar5 == 99)) || (uVar5 == 0x68)) {
        iVar9 = FUN_00004400(uVar15,*puVar11,uVar14,uVar10);
        if (iVar9 != 0) {
          FUN_00006edc(uVar14 & 0xff,iVar9);
          FUN_00008306(3,uVar14 & 0xff,(uVar14 & 0xffffff) >> 0x14,(uVar14 & 0x7ffffff) >> 0x18);
        }
      }
      else {
        iVar9 = FUN_000055c0(uVar14,uVar10,uVar15,puVar11);
      }
    }
    break;
  case 0x2f:
    FUN_000024c4(*param_2);
    break;
  case 0x30:
LAB_00004bb4:
    uVar10 = param_2[1];
    uVar14 = param_2[2];
    goto LAB_00004bce;
  case 0x31:
LAB_00004bbe:
    iVar9 = FUN_00004480(param_2[1],param_2[2]);
    if (iVar9 != 0) break;
    uVar10 = param_2[3];
    uVar14 = 4;
LAB_00004bce:
    iVar9 = FUN_00004480(uVar10,uVar14);
    if ((iVar9 == 0) && (*param_2 < 0x80000000)) {
      iVar9 = 0xf;
    }
    break;
  case 0x33:
LAB_00004a38:
    uVar14 = *param_2;
    uVar10 = param_2[1];
    puVar11 = (undefined4 *)param_2[2];
    param_2 = (uint *)param_2[3];
    iVar9 = FUN_00004480(uVar14,uVar10);
    bVar16 = iVar9 == 0;
    if (!bVar16) goto LAB_00004960;
    iVar9 = FUN_00004480(puVar11,0x20);
    bVar16 = false;
    if (iVar9 == 0) {
      local_40 = 0x20;
      local_3c = param_2;
      iVar9 = FUN_00002da4(uVar14,uVar10,puVar11,DAT_00004e38);
      break;
    }
LAB_0000496c:
    bVar17 = false;
    if (bVar16) {
      if (puVar11[1] == 2) {
        iVar9 = FUN_00004480(*puVar11,puVar11[2]);
        bVar17 = iVar9 == 0;
        if (!bVar17) goto LAB_000048a6;
      }
      iVar9 = FUN_000044b8(*param_2);
      break;
    }
LAB_0000487c:
    if ((bVar17) && (iVar9 = FUN_00004480(*param_2,param_2[1]), iVar9 == 0)) {
      local_40 = 0;
      iVar9 = FUN_000022aa(param_2[2],*param_2,param_2[1],3);
    }
    break;
  case 0x34:
LAB_00004abe:
    uVar10 = *param_2;
    uVar14 = param_2[1];
    puVar11 = (undefined4 *)param_2[2];
    param_2 = (uint *)param_2[3];
    iVar9 = FUN_00004480(uVar14,puVar11);
    bVar17 = false;
    if (iVar9 == 0) {
      iVar9 = FUN_00005510(uVar14,uVar10,puVar11,param_2);
      break;
    }
LAB_000049dc:
    bVar16 = false;
    if (bVar17) {
      iVar9 = FUN_00004250(*param_2);
      break;
    }
LAB_0000490e:
    if (!bVar16) break;
    iVar9 = FUN_00004480(puVar11[4],puVar11[5]);
    bVar16 = iVar9 == 0;
LAB_0000491a:
    bVar17 = false;
    if (bVar16) {
      iVar9 = FUN_00004480(puVar11[2],puVar11[3]);
      bVar16 = iVar9 == 0;
LAB_00004926:
      bVar17 = false;
      if (bVar16) {
        iVar9 = FUN_00004480(*puVar11,puVar11[1]);
        bVar16 = iVar9 == 0;
LAB_00004932:
        bVar17 = false;
        if (bVar16) {
          iVar9 = FUN_00004480(puVar11[6],puVar11[3]);
          bVar16 = iVar9 == 0;
LAB_0000493e:
          bVar17 = false;
          if (bVar16) {
            iVar9 = FUN_00005044(*param_2);
            break;
          }
          goto LAB_0000487c;
        }
      }
    }
LAB_00004842:
    if (bVar17) {
      iVar9 = FUN_00003da4(*param_2,param_2[1],param_2[2],param_2[3]);
    }
    break;
  case 0x35:
LAB_00004be0:
    iVar9 = FUN_00004480(param_2[1],param_2[2]);
    if (iVar9 != 0) break;
    uVar10 = param_2[2];
    if (uVar10 == 1) {
      uVar18 = FUN_00007dd0(*param_2);
      puVar7 = (undefined1 *)param_2[1];
LAB_00004e6c:
      *puVar7 = uVar18;
      break;
    }
    if (uVar10 == 2) {
      uVar4 = FUN_00007da0();
      *(undefined2 *)param_2[1] = uVar4;
      break;
    }
    if (uVar10 != 4) goto LAB_00004c14;
    uVar10 = FUN_00007db8();
LAB_00004f0e:
    puVar6 = (uint *)param_2[1];
LAB_00004afc:
    *puVar6 = uVar10;
    break;
  case 0x36:
LAB_00004c18:
    uVar14 = param_2[2];
    uVar10 = *param_2;
    if (uVar14 == 1) {
      FUN_000086d4(uVar10,(byte)param_2[1]);
      break;
    }
    if (uVar14 == 2) {
      FUN_000086a4(uVar10,(short)param_2[1]);
      break;
    }
    if (uVar14 == 4) {
      FUN_000086bc(uVar10,param_2[1]);
      break;
    }
LAB_00004c14:
    iVar9 = 5;
    break;
  case 0x37:
LAB_00004c42:
    *DAT_00004e40 = *param_2;
    FUN_00005af0(DAT_00004e44,0xfffd,*param_2,4);
    break;
  case 0x38:
  case 0x3d:
    uVar14 = param_2[2];
    uVar10 = *(uint *)param_2[3];
    iVar9 = FUN_00004480((uint *)param_2[3],4);
    if ((iVar9 != 0) || (iVar9 = FUN_00004480(uVar14,uVar10), iVar9 != 0)) break;
    if ((0xfffffeff < param_2[2]) || (uVar10 < 0x100)) goto LAB_00004ec4;
    if (*param_2 == 0x30) {
      local_30 = *(undefined4 *)(DAT_00004e48 + 0xf0);
      local_34 = CONCAT31(local_34._1_3_,0x1e);
      local_3c = &local_34;
      local_2c = DAT_00004e48;
      local_38 = 1;
      uVar14 = param_2[1];
      puVar11 = (undefined4 *)param_2[2];
      goto LAB_00004cb2;
    }
    if (*param_2 != 0x76) {
      iVar9 = 0x91;
      break;
    }
LAB_00004fee:
    iVar9 = 4;
    break;
  case 0x39:
LAB_00004d9e:
    uVar14 = *param_2;
    uVar10 = param_2[1];
    iVar9 = FUN_00004480(uVar14,uVar10);
    if (iVar9 == 0) {
      FUN_0000192c(uVar14,uVar10);
    }
    break;
  case 0x3e:
    puVar7 = DAT_00004e50;
LAB_00004d92:
    *puVar7 = 1;
    break;
  case 0x43:
    puVar11 = (undefined4 *)*param_2;
    iVar9 = FUN_00004480(puVar11,0x20);
    bVar16 = iVar9 == 0;
    if (!bVar16) goto LAB_0000490e;
    iVar9 = FUN_00004480(puVar11[6],4);
    bVar16 = iVar9 == 0;
    if (!bVar16) goto LAB_0000490e;
    iVar9 = FUN_00004480(puVar11[4],8);
    bVar16 = iVar9 == 0;
    if (!bVar16) goto LAB_0000491a;
    iVar9 = FUN_00004480(puVar11[5],4);
    bVar16 = iVar9 == 0;
    if (!bVar16) goto LAB_00004926;
    iVar9 = FUN_00004480(puVar11[3],4);
    bVar16 = iVar9 == 0;
    if (!bVar16) goto LAB_00004932;
    iVar9 = FUN_00004480(puVar11[1],4);
    bVar16 = false;
    if (iVar9 == 0) {
      iVar9 = FUN_00005f9c(*param_2);
      break;
    }
    goto LAB_0000493e;
  }
LAB_00004638:
  pcVar1 = DAT_000048e0;
  pcVar1[4] = '\0';
  pcVar1[5] = '\0';
  pcVar1[6] = '\0';
  pcVar1[7] = '\0';
  if (iVar13 == 0) {
    iVar13 = iVar9;
  }
  return iVar13;
}

