#include <mutex>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
constexpr size_t numEntries = 1024 * 1024 * 64;

namespace {

static constexpr size_t divide_and_ceil(size_t x, size_t y) {
  return (x + y - 1) / y;
}

static constexpr size_t rnd_up(const size_t a, const size_t b) {
  return (divide_and_ceil(a, b) * b);
}

static constexpr size_t rnd_dn(const size_t a, const size_t b) {
  return (a / b) * b;
}

static void fill_memory(char *start, char *end) {
  memset(start, 0xcc, end - start);
}

static void check(uint8_t *start, uint8_t *end, void *base_buffer,
                  size_t real_sz) {
  for (uint8_t *p = start; p < end; p++) {
    if (*p != 0xcc) {
      fputs("Buffer overflow detected\n", stderr);
      munmap(base_buffer, real_sz);
      std::abort();
    }
  }
}
struct Env {
  char *mem;
  uint64_t *freeList;
  std::mutex lock;
  size_t pageSize = getpagesize();

  Env() {
    mem = (char *)mmap(nullptr, numEntries * pageSize, PROT_NONE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    freeList = (uint64_t *)mmap(nullptr, numEntries * sizeof(uint64_t),
                                PROT_READ | PROT_WRITE,
                                MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  }

  void *alloc(size_t size, size_t alignment) {
    if (size == 0) {
      size = 1;
    }
    size_t data_size = rnd_up(size, pageSize);
    size_t real_sz = data_size + pageSize * 2;
    size_t num_pages = real_sz / pageSize;
    char *ret = nullptr;
    {
      std::lock_guard<std::mutex> guard{lock};
      for (size_t i = 0; i < numEntries; i++) {
        if (freeList[i] == 0) {
          bool done = true;
          for (size_t j = i + 1; j < i + num_pages; j++) {
            if (freeList[j] != 0) {
              done = false;
              break;
            }
          }
          if (!done) {
            continue;
          }
          ret = mem + i * pageSize;
          for (size_t j = i; j < i + num_pages; j++) {
            freeList[j] = size;
          }
          break;
        }
        // else
        // {
        //     uint8_t *buffer;
        //     size_t real_sz;
        //     doCheck(mem + i, buffer, real_sz);
        // }
      }
    }
    if (!ret) {
      std::abort();
    }
    // mprotect(ret, pageSize, PROT_NONE);
    auto protect_page_rhs = (char *)ret + real_sz - pageSize;
    // mprotect(protect_page_rhs, pageSize, PROT_NONE);
    mprotect(ret + pageSize, data_size, PROT_READ | PROT_WRITE);
    auto result = protect_page_rhs - rnd_up(size, alignment);
    fill_memory(result + size, protect_page_rhs);
    fill_memory((char *)ret + pageSize, result);
    return result;
  }

  uint64_t doCheck(void *addr, uint8_t *&buffer, size_t &real_sz) {
    size_t page_sz = pageSize;
    int64_t idx = ((char *)addr - mem) / pageSize;
    if (idx < 0 || idx >= numEntries) {
      std::abort();
    }
    size_t sz = freeList[idx];
    size_t data_size = rnd_up(sz, page_sz);
    real_sz = data_size + page_sz * 2;
    buffer = (uint8_t *)(rnd_dn((size_t)addr, page_sz) - page_sz);
    auto protect_page_rhs = (uint8_t *)buffer + real_sz - page_sz;
    check((uint8_t *)addr + sz, protect_page_rhs, buffer, real_sz);
    check(buffer + page_sz, (uint8_t *)addr, buffer, real_sz);
    return idx;
  }

  void dealloc(void *ptr) {
    uint8_t *buffer;
    size_t real_sz;
    {
      std::lock_guard<std::mutex> guard{lock};
      auto idx = doCheck(ptr, buffer, real_sz);
      auto real_pages = real_sz / pageSize;
      for (auto i = idx - 1; i < idx - 1 + real_pages; i++) {
        freeList[i] = 0;
      }
      mprotect(buffer, real_sz, PROT_NONE);
    }
  }
};
static Env &env() {
  static Env ret;
  return ret;
}
}; // namespace

void *malloc(size_t size) { return env().alloc(size, 8); }
void *calloc(size_t size, size_t n) {
  auto ret = env().alloc(size * n, 8);
  memset(ret, 0, size * n);
  return ret;
}
void *realloc(void *p, size_t newsize) {
  auto ret = env().alloc(newsize, 8);
  memcpy(ret, p, newsize);
  env().dealloc(p);
  return ret;
}

void free(void *p) { env().dealloc(p); }

void *__libc_malloc(size_t size) { return env().alloc(size, 8); }
void *__libc_calloc(size_t n, size_t size) {
  auto ret = env().alloc(size * n, 8);
  memset(ret, 0, size * n);
  return ret;
}
void *__libc_realloc(void *p, size_t newsize) {
  auto ret = env().alloc(newsize, 8);
  memcpy(ret, p, newsize);
  env().dealloc(p);
  return ret;
}
void __libc_free(void *p) { env().dealloc(p); }

void *__libc_valloc(size_t size) { return env().alloc(size, env().pageSize); }
void *__libc_pvalloc(size_t size) { return env().alloc(size, env().pageSize); }
void *__libc_memalign(size_t alignment, size_t size) {
  return env().alloc(size, alignment);
}
int __posix_memalign(void **p, size_t alignment, size_t size) {
  *p = env().alloc(size, alignment);
  return 0;
}

void *memalign(size_t alignment, size_t size) {
  return env().alloc(size, alignment);
}
void *_aligned_malloc(size_t alignment, size_t size) {
  return env().alloc(size, alignment);
}
void *aligned_alloc(size_t alignment, size_t size) {
  return env().alloc(size, alignment);
}
