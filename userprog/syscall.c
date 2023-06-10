#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "threads/palloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file_name);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int fork(const char *thread_name, struct intr_frame *f);
int exec(const char *cmd_line);
int wait(int pid);

/* System call.
 *
 * Previously system call services was handled by the interrupt hand         ler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. 
 이전에는 시스템 콜 서비스가 인터럽트 핸들러(예: 리눅스의 int 0x80)로 처리되었습니다.
그러나 x86-64에서는 제조업체가 효율적인 시스템 콜 요청 경로인 syscall 명령을 제공합니다.
syscall 명령은 모델별 특수 레지스터(Model Specific Register, MSR)에서 값을 읽어오는 방식으로 작동합니다.
자세한 내용은 매뉴얼을 참조하십시오.*/

#define MSR_STAR 0xc0000081         /* Segment selector msr 세그먼트 선택자 MSR */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target  롱 모드 SYSCALL 대상*/
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags EFLAGS에 대한 마스크 */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
			lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int syscall_n = f-> R.rax;
	switch (syscall_n)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f -> R.rax = fork(f->R.rdi, f);
		break;
	case SYS_EXEC:
		f -> R.rax = exec(f->R.rdi);
		break;
	case SYS_WAIT:
		f -> R.rax = wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f -> R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f -> R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f -> R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f -> R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f -> R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f -> R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
	}
	// printf ("system call!\n");
	// thread_exit ();
}

void halt(void)
{
	power_off();
}

void check_address(void *addr)
{
	if(addr == NULL)
		exit(-1);

	if (!is_user_vaddr(addr))
		exit(-1);

	if (pml4_get_page(thread_current()->pml4,addr) == NULL)
		exit(-1);
}

void exit (int status)
{
	struct thread *curr =thread_current();
	curr -> exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

bool create (const char *file, unsigned initial_size){
	check_address(file);
	return filesys_create(file, initial_size);				//주어진 file이름을 가진 이니셜 사이즈 파일을 생성합니다. 
}

bool remove (const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

int open (const char *file_name)
{
	check_address(file_name);
	struct file *file = filesys_open(file_name);
	if (file == NULL)
		return -1;

	int fd =process_add_file(file);
	if (fd == -1)
		file_close(file);

	return fd;
}

int filesize(int fd)
{
	struct file *file =process_get_file(fd);
	if (file == NULL)
		return -1;
	return file_length(file);
}

int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	char *ptr = (char *)buffer;
	int bytes_read =0;

	if (fd == STDIN_FILENO)						//0 (입력 관련된 함수이므로)
	{
		for (int i= 0; i <size; i ++)
		{
			char ch = input_getc();				// 한 문자씩 입력 받는 함수
			if (ch == '\n')						
				break;							// 개행문자 (엔터) 받으면 반복문 종료
			*ptr =ch;							// 입력받은 문자 버퍼(위에서 ptr=buffer )에 저장
			ptr++;								// 버퍼 크기 키우며 저장
			bytes_read++;						// 한번 반복될 때마다 byte_read 증가
		}
	}
	else
	{
		if(fd < 2)		
			return -1;									//1인 경우 반환
		struct file *file = process_get_file(fd);		//fd에 해당하는 포인터 file에 저장
		if (file == NULL)								
			return -1;
		lock_acquire(&filesys_lock);					//락 획득 -> 동시 접근 제한
		bytes_read = file_read(file, buffer, size);		
		//size의 바이트만큼 데이터를 읽어 buffer에 저장, 파일의 위치를 읽은 바이트 수만큼 앞당김
		lock_release(&filesys_lock);
	}
	return bytes_read;
}

int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	int bytes_write = 0;
	if (fd == STDOUT_FILENO)					//1 (출력 관련된 함수이므로)
	{
		putbuf(buffer, size);					//buffer에 있는 데이터 출력
		bytes_write = size;						//변수에 기록한 바이트 수(size) 저장
	}
	else 
	{
		if (fd < 2)								
			return -1;									//0이면 에러
		struct file *file = process_get_file(fd);		//fd에 해당하는 파일 포인터 저장
		if (file == NULL)			
			return -1;
		lock_acquire(&filesys_lock);					//동시접근 제한
		bytes_write = file_write(file ,buffer, size);	
		//buffer에서 size 바이트만큼 데이터를 씀, 파일의 위치를 쓴 바이트 만큼 앞당김 ,, 메모리 확장은 구현되지 않음
		lock_release(&filesys_lock);
	}
	return bytes_write;
}

void seek(int fd, unsigned position)
{
	if (fd < 2)
		return;		//파일 디스크립터 0 > 표준 입력(stdin) ,1 > 표준 출력(stdout)이므로 제외, 0 미만인 경우는 오류기에 차단
	struct file *file = process_get_file(fd);		
	if(file == NULL)
		return;
	file_seek(file, position);	//file이라는 이름을 가진 파일 위치를 position으로 변경
}

unsigned tell(int fd)
{
	if (fd < 2)
		return;
	struct file *file = process_get_file(fd);
	if (file == NULL)
		return;
	return file_tell(file);	//file 이름을 가진 파일의 위치를 바이트 단위로 가져옴
}

void close(int fd)
{
	if (fd < 2)
		return;
	struct file *file = process_get_file(fd);
	if (file == NULL)
		return;
	file_close(file);		//파일을 닫고 관련 자원을 해제함
	process_close_file(fd);	//프로세스 내에서 해당 파일 디스크립터를 닫고 자원을 반환함
}

int fork(const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}

int exec(const char *cmd_line)
{
	check_address(cmd_line);					//주소 확인

	char *cmd_line_copy;						//복제를 위한 임시 버퍼 할당
	cmd_line_copy = palloc_get_page(0);			
	if (cmd_line_copy == NULL)
		exit(-1);
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);	//문자열 복사
	if (process_exec(cmd_line_copy) == -1)		
	//이진파일을 디스크에서 메모리로 로드하고 실행 위치와 사용자 스택의 위치를 설정하여 실행
		exit(-1);
}

int wait(int pid)
{
	return process_wait(pid);
}