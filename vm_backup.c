#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"

extern char data[];  // defined by kernel.ld
pde_t *kpgdir;  // for use in scheduler()

// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void
seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpuid()];
  c->gdt[SEG_KCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
  lgdt(c->gdt, sizeof(c->gdt));
}

void
printvm(pde_t *pgdir1)
{
  pde_t *pde1;
  pde_t *pgdir2;
  pde_t *pde2;
  pte_t *pgtab;
  pte_t *pte;
  int flag = 0;
  //cprintf("Page directory VA: 0x%p\n", &(*pgdir1));
  for(int pd1_index = 0; pd1_index < NPDENTRIES; pd1_index++){
    pde1 = &pgdir1[pd1_index];
    if(*pde1 & PTE_P){ 
      if((*pde1 & PTE_U) == 0){
        continue;
      }
      pgdir2 = (pte_t*)P2V(PG2_ADDR(*pde1));
      for(int pd2_index = 0; pd2_index < NPTENTRIES; pd2_index++){
        pde2 = &pgdir2[pd2_index];
        if(*pde2 & PTE_P){
          if((*pde2 & PTE_U) == 0){
            continue;
          }
          pgtab = (pte_t*)P2V(PTE_ADDR(*pde2));
          for(int pt_index = 0; pt_index < NPTENTRIES; pt_index++){
            pte = &pgtab[pt_index];
            if(*pte & PTE_P){
              if((*pte & PTE_U) == 0){
                continue;
              }
              if(flag == 0){
                cprintf("--- %d: pde1 : 0x%p, pa: 0x%p\n", pd1_index, *pde1, V2P(&(*pgdir1)));
                flag = 1;
              }
              if(flag == 1){
                cprintf("------ %d: pde2 : 0x%p, pa: 0x%p\n", pd2_index, *pde2, V2P(&(*pgdir2)));
                flag = 2;
              }
              if(flag == 2){
                cprintf("-------- %d: pte : 0x%p, pa: 0x%p\n", pt_index, *pte, V2P(&(*pgtab)));
              }
            }
          }
          flag = 0;
        }
      }
    }
  }
}

static pte_t *
pde_walkpgdir(pde_t *pgdir1, const void *va, int alloc) // 3 level paging으로 바꾸기
{
  pde_t *pde1;
  pde_t *pde2;
  pde_t *pgdir2;
  pte_t *pgtab;
  cprintf("walkpgdir\n");
  pde1 = &pgdir1[PD1X(va)];
  if(*pde1 & PTE_P){
    pgdir2 = (pde_t*)P2V(PG1_ADDR(*pde1));
  } else {
    if(!alloc || (pgdir2 = (pte_t*)kalloc()) == 0) // kalloc() : 새로운 physical page 할당 
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgdir2, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde1 = V2P(pgdir2) | PTE_P | PTE_W | PTE_U;
    //return &pgdir2[PD2X(va)];
  }

  pde2 = &pgdir2[PD2X(va)];
  if(*pde2 & PTE_P){
    pgtab = (pte_t*)P2V(PG2_ADDR(*pde2));
  } else{
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    memset(pgtab, 0, PGSIZE);
    *pde2 = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
    //return 0;
  }
  return &pgdir2[PD2X(va)];
}

static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;
  //cprintf("k_walkpgdir\n"); -> 렉먹음
  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

static pte_t *
walkpgdir11(pde_t *pgdir, const void *va, int alloc) // 3 level paging으로 바꾸기
{
  pde_t *pde1;
  pde_t *pde2;
  pde_t *pgdir2;
  pte_t *pgtab;
  cprintf("walkpgdir\n");
  pde1 = &pgdir[PD1X(va)];
  if(*pde1 & PTE_P){
    pgdir2 = (pde_t*)P2V(PG1_ADDR(*pde1));
    
  } else {
    if(!alloc || (pgdir2 = (pte_t*)kalloc()) == 0) // kalloc() : 새로운 physical page 할당 
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgdir2, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde1 = V2P(pgdir2) | PTE_P | PTE_W | PTE_U;
    //return 0;
    //return &pgdir2[PD2X(va)];
  }

  pde2 = &pgdir2[PD2X(va)];
  if(*pde2 & PTE_P){
    pgtab = (pte_t*)P2V(PG2_ADDR(*pde2));
  } else{
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    memset(pgtab, 0, PGSIZE);
    *pde2 = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
    //return 0;
  }
  return &pgtab[PTX(va)];
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
static pte_t *
k_walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;
  //cprintf("k_walkpgdir\n"); -> 렉먹음
  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm, int is_kernel)
{
  char *a, *last;
  pte_t *pte;
  cprintf("--------start mappages--------\n");
  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if(is_kernel == 1){
      //cprintf("here in kernel mappages\n");
      if((pte = k_walkpgdir(pgdir, a, 1)) == 0){
        cprintf("here in kernel mappages222\n");
        return -1;
      }
    }
    else{
      //clprintf("here in mappages\n");
      //clprintf("is_kernel : %d\n", is_kernel);
      if((pte = walkpgdir(pgdir, a, 1)) == 0){
        cprintf("here in mappages222\n");
        return -1;
      } 
    }
    //clprintf("why--\n");
    if(*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap {
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
 { (void*)KERNBASE, 0,             EXTMEM,    PTE_W}, // I/O space
 { (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0},     // kern text+rodata
 { (void*)data,     V2P(data),     PHYSTOP,   PTE_W}, // kern data+memory
 { (void*)DEVSPACE, DEVSPACE,      0,         PTE_W}, // more devices
};

// Set up kernel part of a page table.
pde_t*
setupkvm(int is_kernel)
{
  pde_t *pgdir;
  struct kmap *k;

  if((pgdir = (pde_t*)kalloc()) == 0)
    return 0;
  memset(pgdir, 0, PGSIZE);
  if (P2V(PHYSTOP) > (void*)DEVSPACE)
    panic("PHYSTOP too high");
  for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if(mappages(pgdir, k->virt, k->phys_end - k->phys_start,
                (uint)k->phys_start, k->perm, is_kernel) < 0) {
      freevm(pgdir);
      return 0;
    }
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void
kvmalloc(void)
{
  kpgdir = setupkvm(1);
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void
switchkvm(void)
{
  lcr3(V2P(kpgdir));   // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void
switchuvm(struct proc *p)
{
  if(p == 0)
    panic("switchuvm: no process");
  if(p->kstack == 0)
    panic("switchuvm: no kstack");
  if(p->pgdir == 0)
    panic("switchuvm: no pgdir");

  pushcli();
  mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts,
                                sizeof(mycpu()->ts)-1, 0);
  mycpu()->gdt[SEG_TSS].s = 0;
  mycpu()->ts.ss0 = SEG_KDATA << 3;
  mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
  // setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
  // forbids I/O instructions (e.g., inb and outb) from user space
  mycpu()->ts.iomb = (ushort) 0xFFFF;
  ltr(SEG_TSS << 3);
  lcr3(V2P(p->shadow_pgdir));  // switch to process's address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void
inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W|PTE_U, 0);
  memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int
loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if((uint) addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, addr+i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, P2V(pa), offset+i, n) != n)
      return -1;
  }
  return 0;
}

// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int
allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  char *mem;
  uint a;

  if(newsz >= KERNBASE)
    return 0;
  if(newsz < oldsz)
    return oldsz;

  a = PGROUNDUP(oldsz);
  for(; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pgdir, (char*)a, PGSIZE, V2P(mem), PTE_W|PTE_U, 0) < 0){
      cprintf("allocuvm out of memory (2)\n");
      deallocuvm(pgdir, newsz, oldsz);
      kfree(mem);
      return 0;
    }
  }
  return newsz;
}

int
deallocuvm2(pde_t *pgdir, uint oldsz, uint newsz)
{
  pte_t *pte;
  pde_t *pde; // revised by koo
  uint a, pa;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  cprintf("--------start deallocuvm2--------\n");
  for(; a < oldsz; a += PGSIZE){
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte){
      a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
      //a = PG1ADDR(PD1X(a) + 1, 0, 0, 0) - PGSIZE;
    }
      
    else if((*pte & PTE_P) != 0){
      pa = PTE_ADDR(*pte);
      if(pa == 0)
        panic("kfree");
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
    }
  }
  cprintf("--------finish deallocuvm2--------\n");
  return newsz;
}


// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int
deallocuvm(pde_t *pgdir, uint oldsz, uint newsz) // deallocuvm(pgdir, KERNBASE, 0);
{
  pte_t *pte;
  pde_t *pde; // revised by koo
  uint a, pa;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  deallocuvm2(pgdir, KERNBASE, 0);
  cprintf("--------start deallocuvm--------\n");
  for(; a < oldsz; a += PGSIZE*1024){
    
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte){
      //a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
      // 여기서부터 추가함

      a = PG1ADDR(PD1X(a) + 1, 0, 0, 0) - PGSIZE;
      // for(; a  < oldsz; a += PGSIZE){
      //   cprintf("################\n");
      //   pde = pde_walkpgdir(pgdir, (char*)a, 0);
      //   if(!pde)
      //     a = PG1ADDR(PD1X(a), PD2X(a) + 1, 0, 0) - PGSIZE;
      //   else if((*pde & PTE_P) != 0){
      //     pa = PG1_ADDR(*pde);
      //     if(pa == 0)
      //       panic("kfree");
      //     char *v = P2V(pa);
      //     kfree(v);
      //     *pde = 0;
      //   }
      // }
      // 여기까지
    }
      
    else if((*pte & PTE_P) != 0){
      pa = PTE_ADDR(*pte);
      if(pa == 0)
        panic("kfree");
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
    }
  }
  cprintf("--------finish deallocuvm--------\n");
  return newsz;
}

void
freevm1111(pde_t *pgdir)
{
  uint i;
  if(pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(pgdir, KERNBASE, 0);
  for(i = 0; i < NPDENTRIES; i++){
    if(pgdir[i] & PTE_P){
      char * v = P2V(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
  kfree((char*)pgdir);
}

// Free a page table and all the physical memory pages
// in the user part.
void
freevm(pde_t *pgdir)
{
  uint i, j;
  pde_t *pde1, *pde2;
  pde_t *pgdir2;
  pte_t *pgtab;
  if(pgdir == 0)
    panic("freevm: no pgdir");
  cprintf("--------freevm--------\n");
  deallocuvm(pgdir, KERNBASE, 0);
  cprintf("--------finish freevm--------\n");
  for(i = 0; i < 32; i++){ //NPDENTRIES
    if(pgdir[i] & PTE_P){
      // char * v = P2V(PTE_ADDR(pgdir[i]));
      // kfree(v);

      /////////////////////////////////////
      // pde1 = &pgdir[i];
      // pgdir2 = (pde_t*)P2V(PG1_ADDR(*pde1));

      // for(j = 0; j < 32; j++){
      //   if(pgdir2[j] & PTE_P){
      //     pde2 = &pgdir2[j];
      //     //pgtab = (pde_t*)P2V(PTE_ADDR(*pde2));
      //     char * v2 = P2V(PTE_ADDR(pgdir2[j]));
      //     cprintf("--------kfree v2-------\n");
      //     kfree(v2);
      //   }
      // }
      char * v = P2V(PG2_ADDR(pgdir[i]));
      kfree(v);
      /////////////////////////////////////

      // cprintf("--------kfree v-------\n");
      // char * v = P2V(PG1_ADDR(pgdir[i]));
      // kfree(v);
      // if(*pde2 & PTE_P){
      //   char * v2 = P2V(PG1_ADDR(pgdir2[i]));
      //   cprintf("--------kfree v2-------\n");
      //   kfree(v2);
      // }
      
    }
  }
  cprintf("--------finish freevm 22--------\n");
  kfree((char*)pgdir);
  cprintf("--------finish freevm 33--------\n");
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void
clearpteu(pde_t *pgdir, char *uva)
{
  pte_t *pte;
  pte = walkpgdir(pgdir, uva, 0);
  if(pte == 0)
    panic("clearpteu");
  *pte &= ~PTE_U;
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t*
copyuvm(pde_t *pgdir, uint sz)
{
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;

  if((d = setupkvm(0)) == 0)
    return 0;
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0)
      panic("copyuvm: pte should exist");
    if(!(*pte & PTE_P))
      panic("copyuvm: page not present");
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, (char*)P2V(pa), PGSIZE);
    if(mappages(d, (void*)i, PGSIZE, V2P(mem), flags, 0) < 0) {
      kfree(mem);
      goto bad;
    }
  }
  return d;

bad:
  freevm(d);
  return 0;
}

//PAGEBREAK!
// Map user virtual address to kernel address.
char*
uva2ka(pde_t *pgdir, char *uva)
{
  pte_t *pte;
  pte = walkpgdir(pgdir, uva, 0);
  if((*pte & PTE_P) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  return (char*)P2V(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int
copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char*)p;
  while(len > 0){
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char*)va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if(n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}

/*
 * Page fault handler can be called while console lock is acquired,
 * and when cprintf() is re-entered, the kernel panics.
 *
 * The LOG macro should be used while performing early debugging only
 * and it'll most likely cause a crash during normal operations.
 */
#define LOG 1
#define clprintf(...) if (LOG) cprintf(__VA_ARGS__)

// Returns physical page address from virtual address
static uint __virt_to_phys(pde_t *pgdir, struct proc *proc, uint va)
{
  uint pa;

  pde_t *pde = &pgdir[PDX(va)];
  pte_t *pgtable = (pte_t*)P2V(PTE_ADDR(*pde));

  pa = PTE_ADDR(pgtable[PTX(va)]) | OWP(va);

  return pa;
}

// Same as __virt_to_phys(), but with extra log
static uint virt_to_phys(const char *log, pde_t *pgdir, struct proc *proc, uint va)
{
  uint pa = __virt_to_phys(pgdir, proc, va);

  clprintf("virt_to_phys: translated \"%s\"(%d)'s VA 0x%x to PA 0x%x (%s)\n", proc->name, proc->pid, va, pa, log);

  return pa;
}

void pagefault(void)
{
  struct proc *proc;
  pde_t *pde;
  pte_t *pgtab;
  pte_t *pte; // koo
  pte_t *pte_origin; // koo
  pde_t *pde_origin; // koo
  pte_t *pgtab_origin; // koo
  uint va;

  clprintf("pagefault++\n");

  proc = myproc();

  // Get the faulting virtual address
  va = rcr2();
  clprintf("Page fault by process \"%s\" (pid: %d) at 0x%x\n", proc->name, proc->pid, va);

  // Print stock pgdir's translation result
  virt_to_phys("pgdir", proc->pgdir, proc, va);

  // Map pgdir's page address to shadow_pgdir's page table
  // XXX

  pde = &proc->shadow_pgdir[PDX(va)];
  //pte = walkpgdir(proc->shadow_pgdir, 0, 1);

  pde_origin = &proc->pgdir[PDX(va)];
  *pde = *pde_origin;
  //clprintf("Allocated pgtable at 0x%p\n", pte);

  pte = k_walkpgdir(proc->shadow_pgdir, 0, 1); ///////// walkpgdir로 바꾸기
  pte_origin = walkpgdir(proc->pgdir, 0, 1);
  *pte = *pte_origin;
  clprintf("Allocated pgtable at 0x%p\n", pte);

  /*
   * Print shadow pgdir's translation result,
   * this should match with stock pgdir's translation result above!
   */
  virt_to_phys("shadow_pgdir", proc->shadow_pgdir, proc, va);

  proc->page_faults++;

  // Load a bogus pgdir to force a TLB flush
  //lcr3(V2P(something));
  // Switch to our shadow pgdir
  lcr3(V2P(proc->shadow_pgdir));

  clprintf("pagefault--\n");
}

//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.

