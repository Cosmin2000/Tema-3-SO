// SPDX-License-Identifier: BSD-3-Clause
/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include "exec_parser.h"

typedef struct segment_page {
	int index; // index-ul paginii
	struct segment_page *next;
} SegmentPage;

static so_exec_t *exec;
static struct sigaction old_segv_action;
static char *execMem; // memoria la care este mapat executabilul.


/* Verifica daca pagina de la index-ul "index" se afla in
 * lista de pagini mapate a segmentului "segment".
 */
int isMapped(int index, so_seg_t *segment)
{
	SegmentPage *page = (SegmentPage *)segment->data;

	if (page == NULL)
		return 0;

	while (page != NULL) {
		if (page->index == index)
			return 1;
		page = page->next;
	}
	return 0;
}

// creeaza un nou element de pagina mapata cu index-ul "index".
SegmentPage *newPage(int index)
{
	SegmentPage *page = malloc(sizeof(struct segment_page));

	page->index = index;
	page->next = NULL;
	return page;
}

// Adauga pagina cu index-ul "index" in lista de pagini mapate
SegmentPage *setPageMapped(SegmentPage *pages, int index)
{
	if (pages == NULL) {
		pages = newPage(index);
		return pages;
	}

	SegmentPage *page = pages;

	while (page->next != NULL)
		page = page->next;

	page->next = newPage(index);
	return pages;
}

//Cauta segmentul in care se afla adresa addr.
so_seg_t *findSegment(char *addr, so_exec_t *exec)
{
	int i = 0;
	//Iterez prin segmente.
	for (i = 0; i < exec->segments_no; i++) {
		so_seg_t *seg = &exec->segments[i];
		if (seg->vaddr <= (uintptr_t)addr && seg->vaddr + seg->mem_size >= (uintptr_t)addr)
			return seg;
	}
	return NULL;
}

static void sigsegvHandler(int signum, siginfo_t *info, void *context)
{
	char *page_fault_addr;
	int rc;
	char *pageMem;
	int page_size = getpagesize();

	// adresa din memorie care a provocate page fault.
	page_fault_addr = (char *)info->si_addr;

	// gasim segmentul.
	so_seg_t *segment = findSegment(page_fault_addr, exec);

	// pagina nu se gaseste in niciun segment
	if (segment == NULL) {
		old_segv_action.sa_sigaction(signum, info, context);
		return;
	}

	// Calculam pagina in care s-a facut page fault.
	int page_index = (int)(page_fault_addr - segment->vaddr) / page_size;

	// Pagina este deja mapata.
	if (isMapped(page_index, segment)) {
		old_segv_action.sa_sigaction(signum, info, context);
		return;
	}

	// Mapez pagina in memorie.
	pageMem = mmap((char *)segment->vaddr + page_size * page_index, page_size, PERM_W, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pageMem == MAP_FAILED)
		exit(errno);
	// Copiez datele din executabil in pagina mapata.
	memcpy(pageMem, execMem + segment->offset + page_index * page_size, page_size);
	// Setez paginii permisiunile segmentului.
	rc = mprotect(pageMem, page_size, segment->perm);
	if (rc < 0)
		exit(errno);
	// Adaugam pagina in lista de pagini mapate.
	segment->data = setPageMapped(segment->data, page_index);

}

int so_init_loader(void)
{
	struct sigaction segv_action;
	int rc;

	// Am initializat structurile si am setat handler-ul.
	segv_action.sa_sigaction = sigsegvHandler;
	sigemptyset(&segv_action.sa_mask);
	sigaddset(&segv_action.sa_mask, SIGSEGV);
	segv_action.sa_flags = SA_SIGINFO;

	rc = sigaction(SIGSEGV, &segv_action, &old_segv_action);
	if (rc < 0)
		return errno;

	return -1;
}

int so_execute(char *path, char *argv[])
{
	struct stat exec_stat;
	int rc;
	int fd;

	fd = open(path,  O_RDONLY);
	if (fd < 0)
		return -1;

	// Aflu dimensiunea executabilul
	rc = fstat(fd, &exec_stat);
	if (rc < 0)
		exit(errno);

	// Mapez executabilul in memorie
	execMem = mmap(0, exec_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (execMem == MAP_FAILED)
		exit(errno);

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	// Demapez executabilul din memorie
	rc = munmap(execMem, exec_stat.st_size);
	if (rc < 0)
		return errno;

	return -1;
}
