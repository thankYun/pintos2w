#include <syscall.h>
#include <stdint.h>
#include "../syscall-nr.h"

__attribute__((always_inline))
static __inline int64_t syscall (uint64_t num_, uint64_t a1_, uint64_t a2_,
		uint64_t a3_, uint64_t a4_, uint64_t a5_, uint64_t a6_) {
	int64_t ret;
	register uint64_t *num asm ("rax") = (uint64_t *) num_;
	register uint64_t *a1 asm ("rdi") = (uint64_t *) a1_;
	register uint64_t *a2 asm ("rsi") = (uint64_t *) a2_;
	register uint64_t *a3 asm ("rdx") = (uint64_t *) a3_;
	register uint64_t *a4 asm ("r10") = (uint64_t *) a4_;
	register uint64_t *a5 asm ("r8") = (uint64_t *) a5_;
	register uint64_t *a6 asm ("r9") = (uint64_t *) a6_;

	__asm __volatile(
			"mov %1, %%rax\n"
			"mov %2, %%rdi\n"
			"mov %3, %%rsi\n"
			"mov %4, %%rdx\n"
			"mov %5, %%r10\n"
			"mov %6, %%r8\n"
			"mov %7, %%r9\n"
			"syscall\n"
			: "=a" (ret)
			: "g" (num), "g" (a1), "g" (a2), "g" (a3), "g" (a4), "g" (a5), "g" (a6)
			: "cc", "memory");
	return ret;
}

/* Invokes syscall NUMBER, passing no arguments, and returns the
   return value as an `int'. */
#define syscall0(NUMBER) ( \
		syscall(((uint64_t) NUMBER), 0, 0, 0, 0, 0, 0))

/* Invokes syscall NUMBER, passing argument ARG0, and returns the
   return value as an `int'. */
#define syscall1(NUMBER, ARG0) ( \
		syscall(((uint64_t) NUMBER), \
			((uint64_t) ARG0), 0, 0, 0, 0, 0))
/* Invokes syscall NUMBER, passing arguments ARG0 and ARG1, and
   returns the return value as an `int'. */
#define syscall2(NUMBER, ARG0, ARG1) ( \
		syscall(((uint64_t) NUMBER), \
			((uint64_t) ARG0), \
			((uint64_t) ARG1), \
			0, 0, 0, 0))

#define syscall3(NUMBER, ARG0, ARG1, ARG2) ( \
		syscall(((uint64_t) NUMBER), \
			((uint64_t) ARG0), \
			((uint64_t) ARG1), \
			((uint64_t) ARG2), 0, 0, 0))

#define syscall4(NUMBER, ARG0, ARG1, ARG2, ARG3) ( \
		syscall(((uint64_t *) NUMBER), \
			((uint64_t) ARG0), \
			((uint64_t) ARG1), \
			((uint64_t) ARG2), \
			((uint64_t) ARG3), 0, 0))

#define syscall5(NUMBER, ARG0, ARG1, ARG2, ARG3, ARG4) ( \
		syscall(((uint64_t) NUMBER), \
			((uint64_t) ARG0), \
			((uint64_t) ARG1), \
			((uint64_t) ARG2), \
			((uint64_t) ARG3), \
			((uint64_t) ARG4), \
			0))

/*
	halt() 함수는 컴퓨터 시스템을 일시적으로 정지시키는 기능을 수행하는 함수입니다.
	이 함수는 주로 저전력 상태로 전환하거나 시스템 자원을 보존하는 목적으로 사용됩니다.
	halt() 함수를 호출하면 현재 실행 중인 프로세스는 정지되며, 
	시스템의 다른 프로세스나 인터럽트에 의해 재개될 때까지 대기합니다.

	halt() 함수는 일반적으로 운영체제의 특권 모드에서만 호출할 수 있습니다.
	사용자 모드에서는 접근 권한이 없어 호출할 수 없습니다. 
	시스템 종료나 전원 관리와 같은 특정 상황에서 halt() 함수가 호출되어 
	시스템을 대기 상태로 전환할 수 있습니다.

	이 함수는 특정 시스템 라이브러리나 운영체제에 따라 구현 방식이 다를 수 있으며,
	플랫폼에 따라 지원되지 않을 수도 있습니다. 
	따라서 halt() 함수의 동작은 시스템에 따라 다를 수 있으므로 
	해당 시스템의 문서나 레퍼런스를 참조해야 합니다.*/
void
halt (void) {
	// power_off();
	syscall0 (SYS_HALT);
	NOT_REACHED ();
}

void
exit (int status) {
	syscall1 (SYS_EXIT, status);
	NOT_REACHED ();
}

pid_t
fork (const char *thread_name){
	return (pid_t) syscall1 (SYS_FORK, thread_name);
}

int
exec (const char *file) {
	return (pid_t) syscall1 (SYS_EXEC, file);
}

int
wait (pid_t pid) {
	return syscall1 (SYS_WAIT, pid);
}

bool
create (const char *file, unsigned initial_size) {
	return syscall2 (SYS_CREATE, file, initial_size);
}

bool
remove (const char *file) {
	return syscall1 (SYS_REMOVE, file);
}

int
open (const char *file) {
	return syscall1 (SYS_OPEN, file);
}

int
filesize (int fd) {
	return syscall1 (SYS_FILESIZE, fd);
}

int
read (int fd, void *buffer, unsigned size) {
	return syscall3 (SYS_READ, fd, buffer, size);
}

int
write (int fd, const void *buffer, unsigned size) {
	return syscall3 (SYS_WRITE, fd, buffer, size);
}

void
seek (int fd, unsigned position) {
	syscall2 (SYS_SEEK, fd, position);
}

unsigned
tell (int fd) {
	return syscall1 (SYS_TELL, fd);
}

void
close (int fd) {
	syscall1 (SYS_CLOSE, fd);
}

int
dup2 (int oldfd, int newfd){
	return syscall2 (SYS_DUP2, oldfd, newfd);
}

void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	return (void *) syscall5 (SYS_MMAP, addr, length, writable, fd, offset);
}

void
munmap (void *addr) {
	syscall1 (SYS_MUNMAP, addr);
}

bool
chdir (const char *dir) {
	return syscall1 (SYS_CHDIR, dir);
}

bool
mkdir (const char *dir) {
	return syscall1 (SYS_MKDIR, dir);
}

bool
readdir (int fd, char name[READDIR_MAX_LEN + 1]) {
	return syscall2 (SYS_READDIR, fd, name);
}

bool
isdir (int fd) {
	return syscall1 (SYS_ISDIR, fd);
}

int
inumber (int fd) {
	return syscall1 (SYS_INUMBER, fd);
}

int
symlink (const char* target, const char* linkpath) {
	return syscall2 (SYS_SYMLINK, target, linkpath);
}

int
mount (const char *path, int chan_no, int dev_no) {
	return syscall3 (SYS_MOUNT, path, chan_no, dev_no);
}

int
umount (const char *path) {
	return syscall1 (SYS_UMOUNT, path);
}
