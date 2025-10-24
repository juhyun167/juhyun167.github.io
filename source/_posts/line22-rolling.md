---
title: "[LINE CTF 2022] rolling"
date: 2022-08-28 22:14:25
tags:
categories: [Security, CTF]
---

# 개요

> what you know about rolling?

[<i class="fa-solid fa-file"></i> rolling.apk](/uploads/line22-rolling/rolling.apk)


## 문제 분석

<blockquote class="callout-warning">
    <p>
    <strong>주의사항</strong><br>
    이 글의 내용을 따라하기 위해서는 Aarch64 아키텍처 기반의 안드로이드 장치가 필요합니다. 
    </p>
</blockquote>

안드로이드 APK 파일 `rolling.apk` 가 주어집니다. ADB를 이용하여 안드로이드 장치에 설치한 후 실행하면 그림과 같이 `EditText` 위젯과 버튼이 있는데, 아무 텍스트나 입력하고 버튼을 누르면 앱이 강제종료됩니다.

![1.png](/images/line22-rolling/1.png)

런처 액티비티인 `MainActivity` 의 디컴파일 결과를 보면 10행에 `checkFlag` 메소드, 19행에 `deep` 네이티브 메소드가 선언되어 있습니다. `checkFlag` 메소드는 위의 화면에서 버튼을 누르면 호출되는 메소드입니다. 이 메소드는 `EditText` 위젯에 특정 URL을 입력하면 "Correct! :)" 문자열을 출력하는데, 그렇다고 플래그를 주는 것은 아닙니다.

```java
package me.linectf.app;

...

public class MainActivity extends AppCompatActivity {
    static {
        System.loadLibrary("native-lib");
    }

    public void checkFlag(View arg6) {
        if(((EditText)this.findViewById(0x7F08006D)).getText().toString() == "IINECFT{youtube.com/watch?v=dQw4w9WgXcQ}") {  // id:editText
            Toast.makeText(this, "Correct! :)", 1).show();
            return;
        }

        Toast.makeText(arg6.getContext(), "Wrong! :(", 1).show();
    }

    public native void deep() {
    }

    @Override  // androidx.appcompat.app.AppCompatActivity
    protected void onCreate(Bundle arg2) {
        super.onCreate(arg2);
        this.setContentView(0x7F0B001C);  // layout:activity_main
    }
}
```

APK 파일에서 `lib/arm64-v8a` 경로에는 64비트 Aarch64 라이브러리인 `libnative-lib.so` 파일이 있습니다. 안드로이드 앱은 JNI(Java Native Interface)를 이용해 Java로 작성된 앱 코드에서 C/C++로 작성된 네이티브 라이브러리를 불러오고 코드를 실행할 수 있습니다. 이 파일은 앱에서 불러오는 네이티브 라이브러리에 해당하는 것입니다. 앞서 `MainActivity` 에서 `System.loadLibrary` 를 호출하여 라이브러리를 불러오면 `JNI_OnLoad` 함수가 호출됩니다. 이 함수를 살펴보면 7행에서 라이브러리의 `deep` 함수를 앱에서 호출할 수 있는 네이티브 메소드로 등록하고 있습니다.

```c
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
  ...
  (*vm)->GetEnv(vm, (void **)&env, 65542LL);
  c = (*env)->FindClass(env, "me/linectf/app/MainActivity");
  (*env)->GetObjectClass(env, c);
  (*env)->RegisterNatives(env, c, methods, 1LL);// JNINativeMethod methods[] = {
                                                //     "deep", "()V", reintepret_cast<void*>(deep)
                                                // };
  v3 = (*env)->GetMethodID(env, c, "checkFlag", "(Landroid/view/View;)V");
  v4 = (*env)->GetMethodID(env, c, "deep", "()V");
  v5 = (*env)->ToReflectedMethod(env, c, v3, 0LL);
  v6 = (*env)->ToReflectedMethod(env, c, v4, 0LL);
  v7 = (*env)->FindClass(env, "java/lang/reflect/Executable");
  v8 = (*env)->GetFieldID(env, v7, "artMethod", "J");
  v9 = (unsigned int *)(*env)->GetLongField(env, v5, v8);
  v10 = (unsigned int *)(*env)->GetLongField(env, v6, v8);
  v11 = *v9;
  v12 = *v10;
  *(_DWORD *)((char *)&qword_58 + v12) = *(_DWORD *)((char *)&qword_58 + v11);
  *(_DWORD *)(v12 + 120) = *(_DWORD *)(v11 + 120);
  *v9 = v12;
  v9[1] = v10[1] | 1;
  v9[2] = v10[2];
  *((_WORD *)v9 + 9) = *((_WORD *)v10 + 9);
  *(_OWORD *)(v9 + 6) = *(_OWORD *)(v10 + 6);
  *((_QWORD *)v9 + 5) = *((_QWORD *)v10 + 5);
  return 65542;
}
```

그런데 10행 이후의 코드를 보면 `GetMethodID` , `ToReflectedMethod` 등 JNI 함수들을 이용한 추가적인 작업을 하고 있습니다. 여기서 `ToReflectedMethod` 함수는 안드로이드 NDK [위키](https://github.com/android/ndk/wiki/JNI#jnienv)를 보면 Java 리플렉션(reflection)과의 상호작용을 위한 함수라고 명시되어 있습니다. 리플렉션은 런타임에 객체의 멤버들에 대한 정보를 조회하고 조작할 수 있는 Java 언어의 기능입니다. 이를 참고할 때, 리플렉션을 이용해 `checkFlag` 의 `artMethod` 값을 `deep` 의 값으로 덮어씌워 런타임에 `checkFlag` 메소드를 호출하면 `deep` 네이티브 메소드가 호출되도록 조작하고 있음을 추측할 수 있습니다.

라이브러리에서 `deep` 함수를 살펴보면 `MainActivity` 의 `EditText` 위젯에 입력된 문자열을 가져와 반복문을 실행합니다. 반복문은 문자열 내의 각 문자 `s[i]` 에 대해 `meatbox` , `soulbox` , `godbox` 함수를 실행하여 결과가 각각 `data[i]` , `data[i + 1]` , `data[i + 2]` 와 모두 같은지 검사합니다. 모든 문자에 대해 검사를 통과하면 "Correct! :)" 를 출력합니다. 따라서 이를 만족하는 문자열이 플래그라고 짐작할 수 있습니다.

```c
__int64 __fastcall deep(JNIEnv *env, __int64 a2, __int64 a3)
{
    ...
    if ( (stat("/bin/su", (struct stat *)v51) & 0x80000000) != 0
      && (stat("/bin/magisk", (struct stat *)v51) & 0x80000000) != 0 )
    {
      v50 = v19;
      v27 = (*env)->FindClass(env, "me/linectf/app/R$id");
      v28 = (*env)->GetStaticFieldID(env, v27, "editText", "I");
      (*env)->GetStaticIntField(env, v27, v28);
      v29 = (*env)->FindClass(env, "me/linectf/app/MainActivity");
      v30 = (*env)->GetMethodID(env, v29, "findViewById", "(I)Landroid/view/View;");
      v31 = _JNIEnv::CallObjectMethod(env, a2, v30);
      v32 = (*env)->FindClass(env, "android/widget/EditText");
      v33 = (*env)->GetMethodID(env, v32, "getText", "()Landroid/text/Editable;");
      v34 = _JNIEnv::CallObjectMethod(env, v31, v33);
      v35 = (*env)->FindClass(env, "android/text/Editable");
      v36 = (*env)->GetMethodID(env, v35, "toString", "()Ljava/lang/String;");
      v37 = (void *)_JNIEnv::CallObjectMethod(env, v34, v36);
      s = (*env)->GetStringUTFChars(env, v37, 0LL);
      j = 0;
      i = 0LL;
      failed = 0;
      while ( strlen(s) > i )
      {
        sub_3C48(buf, v42, v43, v44, (unsigned __int8)s[i]);// vsnprintf(buf, 2, "%c', s[i])
        v45 = (unsigned __int8 *)meatbox(buf);
        v46 = (unsigned __int8 *)soulbox(buf);
        v47 = (unsigned __int8 *)godbox(buf);
        if ( data[j] != *v45 || data[j + 1] != *v46 || data[j + 2] != *v47 )
          failed = 1;
        ++i;
        j += 3;
      }
      if ( failed == 1 || strlen(s) <= 50uLL )
      {
        v48 = *env;
        v49 = "Wrong! :(";
      }
      else
      {
        v48 = *env;
        v49 = "Correct! :)";
      }
```


## 문제 풀이

플래그를 얻기 위해서는 라이브러리에 구현된 `meatbox` , `soulbox` , `godbox` 함수의 인자로 전달했을 때 결과가 `data` 배열의 값들과 일치하는 문자열을 구해야 합니다. 그런데 이들 함수의 구현은 매우 복잡하여 분석이 쉽지 않습니다. 라이브러리 또한 안드로이드 NDK로 컴파일된 라이브러리로 일반적인 Aarch64 환경에서 동적 분석을 시도하여도 의존성 문제로 인해 로딩조차 되지 않습니다. 따라서 해당 라이브러리를 동적으로 로딩하여 `meatbox` , `soulbox` , `godbox` 함수를 호출하는 C 코드를 작성하고, 안드로이드 NDK로 컴파일한 후 Aarch64 기반의 안드로이드 장치에서 실행하도록 하겠습니다.

안드로이드 NDK는 C/C++로 작성한 코드를 안드로이드에서 실행 가능하도록 하는 빌드 도구입니다. 안드로이드 통합 개발 환경인 안드로이드 스튜디오(Android Studio)의 SDK Manager 메뉴에서 다음과 같이 설치할 수 있습니다.

![2.png](/images/line22-rolling/2.png)

안드로이드 NDK 설치 경로의 clang 컴파일러를 이용해 소스 코드를 컴파일하고, ADB를 이용하여 바이너리를 장치에 전송하는 빌드 스크립트를 다음과 같이 작성하였습니다. 설치 경로는 운영체제에 따라 서로 다를 수 있습니다.

```bash
#!/usr/bin/env bash

# add to terminal PATH variable
export PATH="$HOME/Library/Android/sdk/ndk/25.1.8937393/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"

# make alias CC to be the new clang binary
export CC=aarch64-linux-android29-clang

$CC main.c -o main

# push compiled binary to android
adb push main /data/local/tmp
```

라이브러리를 로드할 때 유의할 점은 해당 라이브러리는 C++로 작성되어, 함수 이름이 맹글링(mangling)되어 있다는 것입니다. `readelf` 를 사용해 라이브러리에서 심볼을 조회하면 `meatbox` , `soulbox` , `godbox` 함수들의 맹글링된 이름을 확인할 수 있습니다. 함수를 불러올 때는 이 이름들을 사용해야 합니다.

```
$ readelf -s .\libnative-lib.so | grep "box"
    ...
    21: 0000000000001708  1040 FUNC    GLOBAL DEFAULT   10 _Z7meatboxPc
    ...
    28: 000000000000314c  1044 FUNC    GLOBAL DEFAULT   10 _Z6godboxPc
    ...
    35: 0000000000002428  1040 FUNC    GLOBAL DEFAULT   10 _Z7soulboxPc
```

풀이 코드는 `dlopen` 과 `dlsym` 함수를 이용해 동적으로 라이브러리를 불러오고 `meatbox` , `soulbox` , `godbox` 함수를 찾아 함수 포인터에 대입합니다. 이후 모든 출력 가능한 ASCII 범위의 문자에 대해 각각의 함수들을 호출하여 결과를 미리 `map` 배열에 저장합니다. `data` 배열의 값들과 결과가 일치하는 문자를 `map` 배열에서 조회하여 플래그를 구할 수 있도록 하였습니다. 안드로이드 장치에 바이너리를 전송하고 실행하면 플래그를 확인할 수 있습니다.

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

char *(*meatbox)(char *);
char *(*soulbox)(char *);
char *(*godbox)(char *);

char data[153] = { 7, 24, 16, 15, 28, 18, 5, 10, 7, 11, 2, 15, 18, 6, 8, 19, 10, 7, 5, 9, 11, 6, 15, 15, 17, 4, 19, 19, 1, 14, 3, 11, 0, 1, 1, 9, 9, 2, 8, 19, 1, 14, 1, 1, 12, 9, 5, 16, 1, 18, 10, 8, 11, 18, 17, 4, 19, 1, 1, 12, 19, 1, 14, 18, 0, 14, 8, 11, 18, 1, 15, 11, 3, 11, 0, 1, 1, 12, 7, 5, 4, 8, 11, 18, 8, 24, 15, 8, 24, 15, 14, 28, 15, 1, 18, 10, 16, 21, 17, 1, 1, 12, 6, 22, 10, 8, 11, 18, 17, 4, 19, 1, 18, 10, 1, 1, 12, 14, 28, 15, 1, 18, 10, 1, 1, 12, 3, 11, 0, 9, 2, 8, 4, 13, 16, 1, 1, 12, 6, 22, 10, 4, 13, 16, 4, 13, 16, 17, 15, 5, 7, 23, 2 };

void setup() {
    void *handle;
    char *error;
    char map[256][3];

    handle = dlopen("./libnative-lib.so", RTLD_LAZY);
    if (!handle) {
        printf("%s\n", dlerror());
        exit(0);
    }
    dlerror();

    meatbox = (char *(*)(char *)) dlsym(handle, "_Z7meatboxPc");
    error = dlerror();
    if (error != NULL) {
        printf("%s\n", error);
        exit(0);
    }
    soulbox = (char *(*)(char *)) dlsym(handle, "_Z7soulboxPc");
    error = dlerror();
    if (error != NULL) {
        printf("%s\n", error);
        exit(0);
    }
    godbox = (char *(*)(char *)) dlsym(handle, "_Z6godboxPc");
    error = dlerror();
    if (error != NULL) {
        printf("%s\n", error);
        exit(0);
    }
}

int main() {
    char buf[2] = { '\0' };
    char map[256][3];           // meatbox, soulbox, godbox
    char flag[64] = { '\0' };

    setup();

    for (int i = 0x20; i < 0x7f; i++) {
        buf[0] = (char) i;
        map[i][0] = meatbox(buf)[0];
        map[i][1] = soulbox(buf)[0];
        map[i][2] = godbox(buf)[0];
    }

    for (int i = 0; i < 51; i++) {
        char m = data[i * 3];
        char s = data[i * 3 + 1];
        char g = data[i * 3 + 2];
        int found = 0;

        for (int j = 0x20; j < 0x7f; j++) {
            if (map[j][0] == m
                    && map[j][1] == s
                    && map[j][2] == g
            ) {
                flag[i] = (char) j;
                found = 1;
            }
        }
        if (!found) {
            printf("fail!\n");
            exit(0);
        }
    }

    printf("%s\n", flag);

    return 0;
}
```

```
$ adb shell
beyond1:/ $ cd /data/local/tmp
beyond1:/data/local/tmp $ ./main
LINECTF{watcha_kn0w_ab0ut_r0ll1ng_d0wn_1n_th3_d33p}
```


## 참고자료

[1] *JNI Functions*, Java Native Interface Specification, 2019. [Online] Available: https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/jniTOC.html