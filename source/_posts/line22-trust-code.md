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

`run` 함수는 `read_code` 함수를 호출하여 `code` 포인터를 반환받습니다. 이후 `code[16]` 부터 32바이트를 `sc.code` 로 복사하고 `execute` 함수를 호출합니다. `sc` 는 `Shellcode` 타입의 객체로, 32바이트 크기의 배열인 `code` 를 유일한 필드로 가지고 있습니다.

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