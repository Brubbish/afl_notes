/*
   american fuzzy lop - type definitions and minor macros（宏指令）
   ------------------------------------------------------
*/

#ifndef _HAVE_TYPES_H
#define _HAVE_TYPES_H

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

/*

   Ugh. There is an unintended compiler / glibc #include glitch caused by
   combining the u64 type an %llu in format strings, necessitating a workaround.

   In essence, the compiler is always looking for 'unsigned long long' for %llu.
   On 32-bit systems, the u64 type (aliased to uint64_t) is expanded to
   'unsigned long long' in <bits/types.h>, so everything checks out.

   But on 64-bit systems, it is #ifdef'ed in the same file as 'unsigned long'.
   Now, it only happens in circumstances where the type happens to have the
   expected bit width, *but* the compiler does not know that... and complains
   about 'unsigned long' being unsafe to pass to %llu.

  处理x64下%llu的定义
 */

#ifdef __x86_64__
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif /* ^__x86_64__ */

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#ifndef MIN
#  define MIN(_a,_b) ((_a) > (_b) ? (_b) : (_a))
#  define MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif /* !MIN */

/*
  ifndef: if not defined, 防止一个源文件多次包含同一个头文件，避免冲突
*/

#define SWAP16(_x) ({ \
    u16 _ret = (_x); \
    (u16)((_ret << 8) | (_ret >> 8)); \
  })

#define SWAP32(_x) ({ \
    u32 _ret = (_x); \
    (u32)((_ret << 24) | (_ret >> 24) | \
          ((_ret << 8) & 0x00FF0000) | \
          ((_ret >> 8) & 0x0000FF00)); \
  })

#ifdef AFL_LLVM_PASS
#  define AFL_R(x) (random() % (x))
#else
#  define R(x) (random() % (x))
#endif /* ^AFL_LLVM_PASS */

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)

#define MEM_BARRIER() \
  __asm__ volatile("" ::: "memory")

/*
  设置内存屏障，即该define的名字
  volatile禁止编译器优化该句
  __asm__ (汇编语句: 输出部分: 输入部分: 破坏描述部分)
  破坏描述部分：通知编译器该代码使用了哪些寄存器或内存，

  内存屏障：
  https://blog.csdn.net/szhlcy/article/details/102560866
  https://stackoverflow.com/questions/14950614/working-of-asm-volatile-memory

  内存访问速度远不及CPU处理速度，为提高机器整体性能，
  在硬件上引入硬件高速缓存Cache和乱序执行，这个大家都知道了
  软件一级的优化：一种是在编写代码时由程序员优化，另一种是
  由编译器进行优化。编译器优化常用的方法有：将内存变量缓存
  到寄存器；调整指令顺序充分利用CPU指令流水线，常见的是重
  新排序读写指令。对常规内存进行优化的时候，这些优化是透明
  的，而且效率很好。由编译器优化或者硬件重新排序引起的问题
  的解决办法是在从硬件（或者其他处理器）的角度看必须以特定
  顺序执行的操作之间设置内存屏障（memory barrier），linux 
  提供了一个宏void Barrier(void)解决编译器的执行顺序问题。
  这个函数通知编译器插入一个内存屏障，但对硬件无效，编译后
  的代码会把当前CPU寄存器中的所有修改过的数值存入内存，需
  要这些数据的时候再重新从内存中读出。
*/




#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

/*
  可能性
  表示_x的可能性更大（小）
  注意到：
  if(likely(value))  //等价于 if(value)
  if(unlikely(value))  //也等价于 if(value)
  使用likely()，执行 if 后面的语句的机会更大，使用 unlikely()，执行 else 后面的语句的机会更大
*/

#endif /* ! _HAVE_TYPES_H */
