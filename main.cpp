#if 0
LLVM_LIBS=`llvm-config --libfiles engine core irreader orcjit`
CXX_FLAGS=`llvm-config --cxxflags`
clang++ $0 -DSTDLIB -g -S -emit-llvm -o ll_stdlib.ll && \
llvm-as ll_stdlib.ll -o ll_stdlib.bc && \
xxd -i ll_stdlib.bc  > ll_stdlib.h && \
clang++ $0 -g $LLVM_LIBS $CXX_FLAGS -lpthread -ldl -lncurses -lz -o ll \
-pedantic-errors -Wall -Wextra -Werror -ferror-limit=1 \
-Wno-c99-extensions -Wno-comment \
-fno-exceptions -fno-rtti -fvisibility=hidden \
-Wno-unused-parameter -Wno-unneeded-internal-declaration \
-Wno-unused-function \
&& \
exit 0
exit 1
#endif
#ifdef STDLIB
extern "C" {
#include <cmath>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
void ll_printf(char const *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stdout, fmt, args);
  va_end(args);
  fflush(stdout);
}
void ll_puts(char const *str) {
  printf(str);
  fflush(stdout);
}
char *ll_format(char *buf, char const *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
  return buf;
}
int  fmt_insert_float(char *buf, int maxlen, float a) { return snprintf(buf, maxlen, "%f", a); }
int  fmt_insert_int(char *buf, int maxlen, int a) { return snprintf(buf, maxlen, "%i", a); }
void ll_debug_assert(bool val, char const *str) {
  if (!val) {
    fprintf(stdout, "[debug] fail: %s\n", str);
  } else {
    fprintf(stdout, "[debug] succ: %s\n", str);
  }
  fflush(stdout);
}
void ll_assert(bool val, char const *str) {
  if (!val) {
    fprintf(stdout, "[assert] fail: %s\n", str);
    fflush(stdout);
    abort();
  }
}
void ll_print_zero() { printf("%f\n", 555.0f); }
}
#else
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Transforms/AggressiveInstCombine/AggressiveInstCombine.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/GVN.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Vectorize.h"
#include <llvm/ExecutionEngine/JITEventListener.h>
#include <llvm/ExecutionEngine/ObjectCache.h>
#include <llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/NoFolder.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if __linux__
// UNIX headers
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "ll_stdlib.h"

extern "C" void  abort();
extern "C" void *malloc(size_t);
extern "C" void  free(void *);

#define ASSERT_ALWAYS(x)                                                                           \
  do {                                                                                             \
    if (!(x)) {                                                                                    \
      fprintf(stderr, "%s:%i [FAIL] at %s\n", __FILE__, __LINE__, #x);                             \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)
#define ASSERT_DEBUG(x) ASSERT_ALWAYS(x)
#define NOTNULL(x) ASSERT_ALWAYS((x) != NULL)
#define ARRAY_SIZE(_ARR) ((int)(sizeof(_ARR) / sizeof(*_ARR)))
#define DLL_EXPORT __attribute__((visibility("default")))
#define ATTR_USED __attribute__((used))

#undef MIN
#undef MAX
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define OFFSETOF(class, field) ((size_t) & (((class *)0)->field))

using u64 = uint64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u8  = uint8_t;
using i64 = int64_t;
using i32 = int32_t;
using i16 = int16_t;
using i8  = int8_t;
using i32 = int32_t;
using f32 = float;
using f64 = double;

template <typename T> T copy(T const &in) { return in; }

template <typename M, typename K> bool contains(M const &in, K const &key) {
  return in.find(key) != in.end();
}

template <typename M> bool sets_equal(M const &a, M const &b) {
  if (a.size() != b.size()) return false;
  for (auto const &item : a) {
    if (!contains(b, item)) return false;
  }
  return true;
}

template <typename M> M get_intersection(M const &a, M const &b) {
  M out;
  for (auto const &item : a) {
    if (contains(b, item)) out.insert(item);
  }
  return out;
}

template <typename T, typename F> bool any(T set, F f) {
  for (auto const &item : set)
    if (f(item)) return true;
  return false;
}

#define UNIMPLEMENTED_(s)                                                                          \
  do {                                                                                             \
    fprintf(stderr, "%s:%i UNIMPLEMENTED %s\n", __FILE__, __LINE__, s);                            \
    abort();                                                                                       \
  } while (0)
#define UNIMPLEMENTED UNIMPLEMENTED_("")
#define TRAP UNIMPLEMENTED_("")
#define NOCOMMIT (void)0

template <typename F> struct __Defer__ {
  F f;
  __Defer__(F f) : f(f) {}
  ~__Defer__() { f(); }
};

template <typename F> __Defer__<F> defer_func(F f) { return __Defer__<F>(f); }

#define DEFER_1(x, y) x##y
#define DEFER_2(x, y) DEFER_1(x, y)
#define DEFER_3(x) DEFER_2(x, __COUNTER__)
#define defer(code) auto DEFER_3(_defer_) = defer_func([&]() { code; })

#define STRINGIFY(a) _STRINGIFY(a)
#define _STRINGIFY(a) #a

#define ito(N) for (uint32_t i = 0; i < N; ++i)
#define jto(N) for (uint32_t j = 0; j < N; ++j)
#define uto(N) for (uint32_t u = 0; u < N; ++u)
#define kto(N) for (uint32_t k = 0; k < N; ++k)
#define xto(N) for (uint32_t x = 0; x < N; ++x)
#define yto(N) for (uint32_t y = 0; y < N; ++y)

#define PERF_HIST_ADD(name, val)
#define PERF_ENTER(name)
#define PERF_EXIT(name)
#define OK_FALLTHROUGH (void)0;
#define TMP_STORAGE_SCOPE                                                                          \
  tl_alloc_tmp_enter();                                                                            \
  defer(tl_alloc_tmp_exit(););
#define SWAP(x, y)                                                                                 \
  do {                                                                                             \
    auto tmp = x;                                                                                  \
    x        = y;                                                                                  \
    y        = tmp;                                                                                \
  } while (0)

#if __linux__
static inline size_t               get_page_size() { return sysconf(_SC_PAGE_SIZE); }
#else
static inline size_t get_page_size() { return 1 << 12; }
#endif

static inline size_t page_align_up(size_t n) {
  return (n + get_page_size() - 1) & (~(get_page_size() - 1));
}

static inline size_t page_align_down(size_t n) { return (n) & (~(get_page_size() - 1)); }

static inline size_t get_num_pages(size_t size) { return page_align_up(size) / get_page_size(); }

#if __linux__
static inline void   protect_pages(void *ptr, size_t num_pages) {
  mprotect(ptr, num_pages * get_page_size(), PROT_NONE);
}
static inline void unprotect_pages(void *ptr, size_t num_pages, bool exec = false) {
  mprotect(ptr, num_pages * get_page_size(), PROT_WRITE | PROT_READ | (exec ? PROT_EXEC : 0));
}

static inline void unmap_pages(void *ptr, size_t num_pages) {
  int err = munmap(ptr, num_pages * get_page_size());
  ASSERT_ALWAYS(err == 0);
}

static inline void map_pages(void *ptr, size_t num_pages) {
  void *new_ptr =
      mmap(ptr, num_pages * get_page_size(), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  ASSERT_ALWAYS((size_t)new_ptr == (size_t)ptr);
}
#else
// Noops
static inline void protect_pages(void *ptr, size_t num_pages) {}
static inline void unprotect_pages(void *ptr, size_t num_pages, bool exec = false) {}
static inline void unmap_pages(void *ptr, size_t num_pages) {}
static inline void map_pages(void *ptr, size_t num_pages) {}
#endif

template <typename T, typename V> struct Pair {
  T    first;
  V    second;
  void bind(T &f, V &s) {
    f = first;
    s = second;
  }
};

template <typename T, typename V> Pair<T, V> make_pair(T t, V v) { return {t, v}; }

template <typename T = uint8_t> struct Pool {
  uint8_t *ptr;
  size_t   cursor;
  size_t   capacity;
  size_t   mem_length;
  size_t   stack_capacity;
  size_t   stack_cursor;

  static Pool create(size_t capacity) {
    ASSERT_DEBUG(capacity > 0);
    Pool   out;
    size_t STACK_CAPACITY = 0x20 * sizeof(size_t);
    out.mem_length        = get_num_pages(STACK_CAPACITY + capacity * sizeof(T)) * get_page_size();
#if __linux__
    out.ptr = (uint8_t *)mmap(NULL, out.mem_length, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
                              -1, 0);
    ASSERT_ALWAYS(out.ptr != MAP_FAILED);
#else
    out.ptr = (uint8_t *)malloc(out.mem_length);
    NOTNULL(out.ptr);
#endif
    out.capacity       = capacity;
    out.cursor         = 0;
    out.stack_capacity = STACK_CAPACITY;
    out.stack_cursor   = 0;
    return out;
  }

  void release() {
#if __linux__
    if (this->ptr) munmap(this->ptr, mem_length);
#else
    if (this->ptr) free(this->ptr);
#endif
    memset(this, 0, sizeof(Pool));
  }

  void push(T const &v) {
    T *ptr = alloc(1);
    memcpy(ptr, &v, sizeof(T));
  }

  bool has_items() { return this->cursor > 0; }

  T *at(uint32_t i) { return (T *)(this->ptr + this->stack_capacity + i * sizeof(T)); }

  T *alloc(size_t size) {
    ASSERT_DEBUG(size != 0);
    T *ptr = (T *)(this->ptr + this->stack_capacity + this->cursor * sizeof(T));
    this->cursor += size;
    ASSERT_DEBUG(this->cursor < this->capacity);
    return ptr;
  }

  T *try_alloc(size_t size) {
    ASSERT_DEBUG(size != 0);
    if (this->cursor + size > this->capacity) return NULL;
    T *ptr = (T *)(this->ptr + this->stack_capacity + this->cursor * sizeof(T));
    this->cursor += size;
    ASSERT_DEBUG(this->cursor < this->capacity);
    return ptr;
  }

  T *alloc_zero(size_t size) {
    T *mem = alloc(size);
    memset(mem, 0, size * sizeof(T));
    return mem;
  }

  T *alloc_align(size_t size, size_t alignment) {
    T *ptr = alloc(size + alignment);
    ptr    = (T *)(((size_t)ptr + alignment - 1) & (~(alignment - 1)));
    return ptr;
  }

  T *alloc_page_aligned(size_t size) {
    ASSERT_DEBUG(size != 0);
    size           = page_align_up(size) + get_page_size();
    T *ptr         = (T *)(this->ptr + this->stack_capacity + this->cursor * sizeof(T));
    T *aligned_ptr = (T *)(void *)page_align_down((size_t)ptr + get_page_size());
    this->cursor += size;
    ASSERT_DEBUG(this->cursor < this->capacity);
    return aligned_ptr;
  }

  void enter_scope() {
    // Save the cursor to the stack
    size_t *top = (size_t *)(this->ptr + this->stack_cursor);
    *top        = this->cursor;
    // Increment stack cursor
    this->stack_cursor += sizeof(size_t);
    ASSERT_DEBUG(this->stack_cursor < this->stack_capacity);
  }

  void exit_scope() {
    // Decrement stack cursor
    ASSERT_DEBUG(this->stack_cursor >= sizeof(size_t));
    this->stack_cursor -= sizeof(size_t);
    // Restore the cursor from the stack
    size_t *top  = (size_t *)(this->ptr + this->stack_cursor);
    this->cursor = *top;
  }

  void reset() {
    this->cursor       = 0;
    this->stack_cursor = 0;
  }

  T *put(T const *old_ptr, size_t count) {
    T *new_ptr = alloc(count);
    memcpy(new_ptr, old_ptr, count * sizeof(T));
    return new_ptr;
  }
  void pop() {
    ASSERT_DEBUG(cursor > 0);
    cursor -= 1;
  }
  bool has_space(size_t size) { return cursor + size <= capacity; }
};

template <typename T = u8> using Temporary_Storage = Pool<T>;

/** Allocates 'size' bytes using thread local allocator
 */
void *tl_alloc(size_t size);
/** Reallocates deleting `ptr` as a result
 */
void *tl_realloc(void *ptr, size_t oldsize, size_t newsize);
void  tl_free(void *ptr);
/** Allocates 'size' bytes using thread local temporal storage
 */
void *tl_alloc_tmp(size_t size);
/** Record the current state of thread local temporal storage
 */
void tl_alloc_tmp_enter();
/** Restore the previous state of thread local temporal storage
 */
void tl_alloc_tmp_exit();

struct string_ref {
  const char *ptr;
  size_t      len;
  string_ref  substr(size_t offset, size_t new_len) { return string_ref{ptr + offset, new_len}; }
};

// for printf
#define STRF(str) (i32) str.len, str.ptr

static inline bool operator==(string_ref a, string_ref b) {
  if (a.ptr == NULL || b.ptr == NULL) return false;
  return a.len != b.len ? false : strncmp(a.ptr, b.ptr, a.len) == 0 ? true : false;
}

static inline uint64_t hash_of(uint64_t u) {
  uint64_t v = u * 3935559000370003845 + 2691343689449507681;
  v ^= v >> 21;
  v ^= v << 37;
  v ^= v >> 4;
  v *= 4768777513237032717;
  v ^= v << 20;
  v ^= v >> 41;
  v ^= v << 5;
  return v;
}

template <typename T> static uint64_t hash_of(T *ptr) { return hash_of((size_t)ptr); }

static inline uint64_t hash_of(string_ref a) {
  uint64_t hash = 5381;
  for (size_t i = 0; i < a.len; i++) {
    hash =
        //(hash << 6) + (hash << 16) - hash + a.ptr[i];
        ((hash << 5) + hash) + a.ptr[i];
  }
  return hash;
}

/** String view of a static string
 */
static inline string_ref stref_s(char const *static_string) {
  if (static_string == NULL || static_string[0] == '\0') return string_ref{.ptr = NULL, .len = 0};
  ASSERT_DEBUG(static_string != NULL);
  string_ref out;
  out.ptr = static_string;
  out.len = strlen(static_string);
  ASSERT_DEBUG(out.len != 0);
  return out;
}

/** String view of a temporal string
  Uses thread local temporal storage
  */
static inline string_ref stref_tmp_copy(string_ref a) {
  string_ref out;
  out.len = a.len;
  ASSERT_DEBUG(out.len != 0);
  char *ptr = (char *)tl_alloc_tmp(out.len);
  memcpy(ptr, a.ptr, out.len);
  out.ptr = (char const *)ptr;
  return out;
}

/** String view of a temporal string
  Uses thread local temporal storage
  */
static inline string_ref stref_tmp(char const *tmp_string) {
  ASSERT_DEBUG(tmp_string != NULL);
  string_ref out;
  out.len = strlen(tmp_string);
  ASSERT_DEBUG(out.len != 0);
  char *ptr = (char *)tl_alloc_tmp(out.len);
  memcpy(ptr, tmp_string, out.len);
  out.ptr = (char const *)ptr;

  return out;
}

static inline string_ref stref_concat(string_ref a, string_ref b) {
  string_ref out;
  out.len = a.len + b.len;
  ASSERT_DEBUG(out.len != 0);
  char *ptr = (char *)tl_alloc_tmp(out.len);
  memcpy(ptr, a.ptr, a.len);
  memcpy(ptr + a.len, b.ptr, b.len);
  out.ptr = (char const *)ptr;
  return out;
}

static inline char const *stref_to_tmp_cstr(string_ref a) {
  ASSERT_DEBUG(a.ptr != NULL);
  char *ptr = (char *)tl_alloc_tmp(a.len + 1);
  memcpy(ptr, a.ptr, a.len);
  ptr[a.len] = '\0';
  return ptr;
}

static inline int32_t stref_find(string_ref a, string_ref b, size_t start = 0) {
  size_t cursor = 0;
  for (size_t i = start; i < a.len; i++) {
    if (a.ptr[i] == b.ptr[cursor]) {
      cursor += 1;
    } else {
      i -= cursor;
      cursor = 0;
    }
    if (cursor == b.len) return (int32_t)(i - (cursor - 1));
  }
  return -1;
}

static inline int32_t stref_find_last(string_ref a, string_ref b, size_t start = 0) {
  int32_t last_pos = -1;
  int32_t cursor   = stref_find(a, b, start);
  while (cursor >= 0) {
    last_pos = cursor;
    if ((size_t)cursor + 1 < a.len) cursor = stref_find_last(a, b, (size_t)(cursor + 1));
  }
  return last_pos;
}

#if __linux__
static inline void make_dir_recursive(string_ref path) {
  TMP_STORAGE_SCOPE;
  if (path.ptr[path.len - 1] == '/') path.len -= 1;
  int32_t sep = stref_find_last(path, stref_s("/"));
  if (sep >= 0) {
    make_dir_recursive(path.substr(0, sep));
  }
  mkdir(stref_to_tmp_cstr(path), 0777);
}
#endif

static inline void dump_file(char const *path, void const *data, size_t size) {
  FILE *file = fopen(path, "wb");
  ASSERT_ALWAYS(file);
  fwrite(data, 1, size, file);
  fclose(file);
}

static inline char *read_file_tmp(char const *filename) {
  FILE *text_file = fopen(filename, "rb");
  ASSERT_ALWAYS(text_file);
  fseek(text_file, 0, SEEK_END);
  long fsize = ftell(text_file);
  fseek(text_file, 0, SEEK_SET);
  size_t size = (size_t)fsize;
  char * data = (char *)tl_alloc_tmp((size_t)fsize + 1);
  fread(data, 1, (size_t)fsize, text_file);
  data[size] = '\0';
  fclose(text_file);
  return data;
}

struct Allocator {
  virtual void *    alloc(size_t)                                     = 0;
  virtual void *    realloc(void *, size_t old_size, size_t new_size) = 0;
  virtual void      free(void *)                                      = 0;
  static Allocator *get_head() {
    struct _Allocator : public Allocator {
      virtual void *alloc(size_t size) override { return tl_alloc(size); }
      virtual void *realloc(void *ptr, size_t old_size, size_t new_size) override {
        return tl_realloc(ptr, old_size, new_size);
      }
      virtual void free(void *ptr) override { tl_free(ptr); }
    };
    static _Allocator alloc;
    return &alloc;
  }
};

struct Default_Allocator {
  static void *alloc(size_t size) { return tl_alloc(size); }
  static void *realloc(void *ptr, size_t old_size, size_t new_size) {
    return tl_realloc(ptr, old_size, new_size);
  }
  static void free(void *ptr) { tl_free(ptr); }
};

template <typename T, size_t grow_k = 0x100, typename Allcator_t = Default_Allocator> //
struct Array {
  T *    ptr;
  size_t size;
  size_t capacity;
  void   init(uint32_t capacity = 0) {
    if (capacity != 0)
      ptr = (T *)Allcator_t::alloc(sizeof(T) * capacity);
    else
      ptr = NULL;
    size           = 0;
    this->capacity = capacity;
  }
  u32  get_size() { return this->size; }
  u32  has_items() { return get_size() != 0; }
  void release() {
    if (ptr != NULL) {
      Allcator_t::free(ptr);
    }
    memset(this, 0, sizeof(*this));
  }
  void resize(size_t new_size) {
    if (new_size > capacity) {
      uint64_t new_capacity = new_size;
      ptr      = (T *)Allcator_t::realloc(ptr, sizeof(T) * capacity, sizeof(T) * new_capacity);
      capacity = new_capacity;
    }
    ASSERT_DEBUG(ptr != NULL);
    size = new_size;
  }
  void reset() { size = 0; }
  void memzero() {
    if (capacity > 0) {
      memset(ptr, 0, sizeof(T) * capacity);
    }
  }
  void push(T elem) {
    if (size + 1 > capacity) {
      uint64_t new_capacity = capacity + grow_k;
      ptr      = (T *)Allcator_t::realloc(ptr, sizeof(T) * capacity, sizeof(T) * new_capacity);
      capacity = new_capacity;
    }
    ASSERT_DEBUG(capacity >= size + 1);
    ASSERT_DEBUG(ptr != NULL);
    memcpy(ptr + size, &elem, sizeof(T));
    size += 1;
  }

  T pop() {
    ASSERT_DEBUG(size != 0);
    ASSERT_DEBUG(ptr != NULL);
    T elem = ptr[size - 1];
    if (size + grow_k < capacity) {
      uint64_t new_capacity = capacity - grow_k;
      ptr      = (T *)Allcator_t::realloc(ptr, sizeof(T) * capacity, sizeof(T) * new_capacity);
      capacity = new_capacity;
    }
    ASSERT_DEBUG(size != 0);
    size -= 1;
    if (size == 0) {
      Allcator_t::free(ptr);
      ptr      = NULL;
      capacity = 0;
    }
    return elem;
  }
  T &operator[](size_t i) {
    ASSERT_DEBUG(i < size);
    ASSERT_DEBUG(ptr != NULL);
    return ptr[i];
  }
};

template <typename T, u32 N, typename Allcator_t = Default_Allocator> //
struct SmallArray {
  T                           local[N];
  size_t                      size;
  Array<T, N * 3, Allcator_t> array;
  void                        init() {
    memset(this, 0, sizeof(*this));
    array.init();
  }
  void release() {
    array.release();
    memset(this, 0, sizeof(*this));
  }
  T &operator[](size_t i) {
    if (i < N)
      return local[i];
    else
      return array[i - N];
  }
  void push(T const &val) {
    if (size < N) {
      local[size++] = val;
    } else {
      array.push(val);
      size++;
    }
  }
  bool has(T elem) {
    ito(size) {
      if ((*this)[i] == elem) return true;
    }
    return false;
  }
};

template <typename K, typename Allcator_t = Default_Allocator, size_t grow_k = 0x100,
          size_t MAX_ATTEMPTS = 0x100>
struct Hash_Set {
  struct Hash_Pair {
    K        key;
    uint64_t hash;
  };
  using Array_t = Array<Hash_Pair, grow_k, Allcator_t>;
  Array_t arr;
  size_t  item_count;
  void    release() {
    arr.release();
    item_count = 0;
  }
  void init() {
    arr.init();
    item_count = 0;
  }
  void reset() {
    arr.memzero();
    item_count = 0;
  }
  i32 find(K key) {
    if (item_count == 0) return -1;
    uint64_t hash = hash_of(key);
    uint64_t size = arr.capacity;
    if (size == 0) return -1;
    uint32_t attempt_id = 0;
    for (; attempt_id < MAX_ATTEMPTS; ++attempt_id) {
      uint64_t id = hash % size;
      if (hash != 0) {
        if (arr.ptr[id].key == key) {
          return (i32)id;
        }
      }
      hash = hash_of(hash);
    }
    return -1;
  }

  bool try_insert(K key) {
    uint64_t hash = hash_of(key);
    uint64_t size = arr.capacity;
    if (size == 0) {
      arr.resize(grow_k);
      arr.memzero();
      size = arr.capacity;
    }
    Hash_Pair pair;
    pair.key  = key;
    pair.hash = hash;
    for (uint32_t attempt_id = 0; attempt_id < MAX_ATTEMPTS; ++attempt_id) {
      uint64_t id = hash % size;
      if (hash != 0) {
        pair.hash = hash;
        if (arr.ptr[id].hash == 0) { // Empty slot
          arr.ptr[id] = pair;
          item_count += 1;
          return true;
        } else if (arr.ptr[id].key == key) { // Override
          arr.ptr[id] = pair;
          return true;
        } else { // collision
          (void)0;
        }
      }
      hash = hash_of(hash);
    }
    return false;
  }

  bool try_resize(size_t new_size) {
    ASSERT_DEBUG(new_size > 0);
    Array_t old_arr        = arr;
    size_t  old_item_count = item_count;
    {
      Array_t new_arr;
      new_arr.init();
      ASSERT_DEBUG(new_size > 0);
      new_arr.resize(new_size);
      new_arr.memzero();
      arr        = new_arr;
      item_count = 0;
    }
    uint32_t i = 0;
    for (; i < old_arr.capacity; ++i) {
      Hash_Pair pair = old_arr.ptr[i];
      if (pair.hash != 0) {
        bool suc = try_insert(pair.key);
        if (!suc) {
          arr.release();
          arr        = old_arr;
          item_count = old_item_count;
          return false;
        }
      }
    }
    old_arr.release();
    return true;
  }

  void remove(K key) {
    if (item_count == 0) return;
    while (true) {
      i32 id = find(key);
      if (id > -1) {
        ASSERT_DEBUG(item_count > 0);
        arr.ptr[id].hash = 0u;
        item_count -= 1;
        if (item_count == 0) {
          arr.release();
        } else if (arr.size + grow_k < arr.capacity) {
          try_resize(arr.capacity - grow_k);
        }

      } else {
        break;
      }
    }
  }

  bool insert(K key) {
    u32  iters = 0x10;
    bool suc   = false;
    while (!(suc = try_insert(key))) {
      u32    resize_iters = 6;
      size_t new_size     = arr.capacity + grow_k;
      bool   resize_suc   = false;
      size_t grow_rate    = grow_k << 1;
      while (!(resize_suc = try_resize(new_size))) {
        if (resize_iters == 0) break;
        new_size += grow_rate;
        grow_rate = grow_rate << 1;
        resize_iters -= 1;
      }
      (void)resize_suc;
      ASSERT_DEBUG(resize_suc == true);
      if (iters == 0) break;
      iters -= 1;
    }
    ASSERT_DEBUG(suc == true);
    return suc;
  }

  bool contains(K key) { return find(key) != -1; }
};

template <typename K, typename V> struct Map_Pair {
  K    key;
  V    value;
  bool operator==(Map_Pair const &that) const { return this->key == that.key; }
};

template <typename K, typename V> u64 hash_of(Map_Pair<K, V> const &item) {
  return hash_of(item.key);
}

template <typename K, typename V, typename Allcator_t = Default_Allocator, size_t grow_k = 0x100,
          size_t MAX_ATTEMPTS = 0x20>
struct Hash_Table {
  using Pair_t = Map_Pair<K, V>;
  Hash_Set<Map_Pair<K, V>, Allcator_t, grow_k, MAX_ATTEMPTS> set;
  void                                                       release() { set.release(); }
  void                                                       init() { set.init(); }

  i32 find(K key) { return set.find(Map_Pair<K, V>{.key = key, .value = {}}); }

  V get(K key) {
    i32 id = set.find(Map_Pair<K, V>{.key = key, .value = {}});
    ASSERT_DEBUG(id >= 0);
    return set.arr[id].key.value;
  }

  V *get_or_null(K key) {
    if (set.item_count == 0) return 0;
    i32 id = set.find(Map_Pair<K, V>{.key = key, .value = {}});
    if (id < 0) return 0;
    return &set.arr[id].key.value;
  }

  bool remove(K key) { return set.remove(Map_Pair<K, V>{.key = key, .value = {}}); }

  bool insert(K key, V value) { return set.insert(Map_Pair<K, V>{.key = key, .value = value}); }

  bool contains(K key) { return set.contains(Map_Pair<K, V>{.key = key, .value = {}}); }

  template <typename F> void iter(F f) {
    ito(set.arr.size) {
      auto &item = set.arr[i];
      if (item.hash != 0) {
        f(item.key);
      }
    }
  }
};

struct Thread_Local {
  Temporary_Storage<> temporal_storage;
  bool                initialized = false;
  ~Thread_Local() { temporal_storage.release(); }
};

thread_local Thread_Local g_tl{};

Thread_Local *get_tl() {
  if (g_tl.initialized == false) {
    g_tl.initialized      = true;
    g_tl.temporal_storage = Temporary_Storage<>::create(64 * (1 << 20));
  }
  return &g_tl;
}

void *tl_alloc_tmp(size_t size) { return get_tl()->temporal_storage.alloc(size); }

void tl_alloc_tmp_enter() { get_tl()->temporal_storage.enter_scope(); }
void tl_alloc_tmp_exit() { get_tl()->temporal_storage.exit_scope(); }

void *tl_alloc(size_t size) { return malloc(size); }

void *tl_realloc(void *ptr, size_t oldsize, size_t newsize) {
  if (oldsize == newsize) return ptr;
  size_t min_size = oldsize < newsize ? oldsize : newsize;
  void * new_ptr  = NULL;
  if (newsize != 0) new_ptr = malloc(newsize);
  if (min_size != 0) {
    memcpy(new_ptr, ptr, min_size);
  }
  if (ptr != NULL) free(ptr);
  return new_ptr;
}

void tl_free(void *ptr) { free(ptr); }

struct List {
  string_ref symbol = {};
  u64        id     = 0;
  List *     child  = NULL;
  List *     next   = NULL;
  string_ref get_symbol() {
    ASSERT_ALWAYS(nonempty());
    return symbol;
  }
  string_ref get_umbrella_string() {
    string_ref out = symbol;
    if (child != NULL) {
      string_ref th = child->get_umbrella_string();
      if (out.ptr == NULL) out.ptr = th.ptr;
      out.len += (size_t)(th.ptr - out.ptr) - out.len + th.len;
    }
    if (next != NULL) {
      string_ref th = next->get_umbrella_string();
      if (out.ptr == NULL) out.ptr = th.ptr;
      out.len += (size_t)(th.ptr - out.ptr) - out.len + th.len;
    }
    return out;
  }
  bool nonempty() { return symbol.ptr != 0 && symbol.len != 0; }
  bool cmp_symbol(char const *str) {
    if (symbol.ptr == NULL) return false;
    return symbol == stref_s(str);
  }
  bool has_child(char const *name) { return child != NULL && child->cmp_symbol(name); }
  template <typename T> void match_children(char const *name, T on_match) {
    if (child != NULL) {
      if (child->cmp_symbol(name)) {
        on_match(child);
      }
      child->match_children(name, on_match);
    }
    if (next != NULL) {
      next->match_children(name, on_match);
    }
  }
  List *get(u32 i) {
    List *cur = this;
    while (i != 0) {
      if (cur == NULL) return NULL;
      cur = cur->next;
      i -= 1;
    }
    return cur;
  }

  int ATTR_USED dump(u32 indent = 0) const {
    ito(indent) fprintf(stdout, " ");
    if (symbol.ptr != NULL) {
      fprintf(stdout, "%.*s\n", (i32)symbol.len, symbol.ptr);
    } else {
      fprintf(stdout, "$\n");
    }
    if (child != NULL) {
      child->dump(indent + 2);
    }
    if (next != NULL) {
      next->dump(indent);
    }
    fflush(stdout);
    return 0;
  }
  void dump_list_graph() {
    List *root     = this;
    FILE *dotgraph = fopen("list.dot", "wb");
    fprintf(dotgraph, "digraph {\n");
    fprintf(dotgraph, "node [shape=record];\n");
    tl_alloc_tmp_enter();
    defer(tl_alloc_tmp_exit());
    List **stack        = (List **)tl_alloc_tmp(sizeof(List *) * (1 << 10));
    u32    stack_cursor = 0;
    List * cur          = root;
    u64    null_id      = 0xffffffffull;
    while (cur != NULL || stack_cursor != 0) {
      if (cur == NULL) {
        cur = stack[--stack_cursor];
      }
      ASSERT_ALWAYS(cur != NULL);
      if (cur->symbol.ptr != NULL) {
        ASSERT_ALWAYS(cur->symbol.len != 0);
        fprintf(dotgraph, "%lu [label = \"%.*s\", shape = record];\n", cur->id,
                (int)cur->symbol.len, cur->symbol.ptr);
      } else {
        fprintf(dotgraph, "%lu [label = \"$\", shape = record, color=red];\n", cur->id);
      }
      if (cur->next == NULL) {
        fprintf(dotgraph, "%lu [label = \"nil\", shape = record, color=blue];\n", null_id);
        fprintf(dotgraph, "%lu -> %lu [label = \"next\"];\n", cur->id, null_id);
        null_id++;
      } else
        fprintf(dotgraph, "%lu -> %lu [label = \"next\"];\n", cur->id, cur->next->id);

      if (cur->child != NULL) {
        if (cur->next != NULL) stack[stack_cursor++] = cur->next;
        fprintf(dotgraph, "%lu -> %lu [label = \"child\"];\n", cur->id, cur->child->id);
        cur = cur->child;
      } else {
        cur = cur->next;
      }
    }
    fprintf(dotgraph, "}\n");
    fflush(dotgraph);
    fclose(dotgraph);
  }
  template <typename T> static List *parse(string_ref text, T allocator) {
    List *root = allocator.alloc();
    List *cur  = root;
    TMP_STORAGE_SCOPE;
    List **stack        = (List **)tl_alloc_tmp(sizeof(List *) * (1 << 8));
    u32    stack_cursor = 0;
    enum class State : char {
      UNDEFINED = 0,
      SAW_QUOTE,
      SAW_LPAREN,
      SAW_RPAREN,
      SAW_PRINTABLE,
      SAW_SEPARATOR,
      SAW_SEMICOLON,
    };
    u32   i  = 0;
    u64   id = 1;
    State state_table[0x100];
    memset(state_table, 0, sizeof(state_table));
    for (u8 j = 0x20; j <= 0x7f; j++) state_table[j] = State::SAW_PRINTABLE;
    state_table[(u32)'(']  = State::SAW_LPAREN;
    state_table[(u32)')']  = State::SAW_RPAREN;
    state_table[(u32)'"']  = State::SAW_QUOTE;
    state_table[(u32)' ']  = State::SAW_SEPARATOR;
    state_table[(u32)'\n'] = State::SAW_SEPARATOR;
    state_table[(u32)'\t'] = State::SAW_SEPARATOR;
    state_table[(u32)'\r'] = State::SAW_SEPARATOR;
    state_table[(u32)';']  = State::SAW_SEMICOLON;

    auto next_item = [&]() {
      List *next = allocator.alloc();
      next->id   = id++;
      if (cur != NULL) cur->next = next;
      cur = next;
    };

    auto push_item = [&]() {
      List *new_head = allocator.alloc();
      new_head->id   = id++;
      if (cur != NULL) {
        stack[stack_cursor++] = cur;
        cur->child            = new_head;
      }
      cur = new_head;
    };

    auto pop_item = [&]() -> bool {
      if (stack_cursor == 0) {
        return false;
      }
      cur = stack[--stack_cursor];
      return true;
    };

    auto append_char = [&]() {
      if (cur->symbol.ptr == NULL) { // first character for that item
        cur->symbol.ptr = text.ptr + i;
      }
      cur->symbol.len++;
    };

    auto cur_non_empty = [&]() { return cur != NULL && cur->symbol.len != 0; };
    auto cur_has_child = [&]() { return cur != NULL && cur->child != NULL; };

    i                = 0;
    State prev_state = State::UNDEFINED;
    while (i < text.len) {
      char  c     = text.ptr[i];
      State state = state_table[(u8)c];
      switch (state) {
      case State::UNDEFINED: {
        goto error_parsing;
      }
      case State::SAW_SEMICOLON: {
        i += 1;
        while (text.ptr[i] != '\n') {
          i += 1;
        }
        break;
      }
      case State::SAW_QUOTE: {
        if (cur_non_empty() || cur_has_child()) next_item();
        if (text.ptr[i + 1] == '"' && text.ptr[i + 2] == '"') {
          i += 3;
          while (text.ptr[i + 0] != '"' || //
                 text.ptr[i + 1] != '"' || //
                 text.ptr[i + 2] != '"') {
            append_char();
            i += 1;
          }
          i += 2;
        } else {
          i += 1;
          while (text.ptr[i] != '"') {
            append_char();
            i += 1;
          }
        }
        break;
      }
      case State::SAW_LPAREN: {
        if (cur_has_child() || cur_non_empty()) next_item();
        push_item();
        break;
      }
      case State::SAW_RPAREN: {
        if (pop_item() == false) goto exit_loop;
        break;
      }
      case State::SAW_SEPARATOR: {
        break;
      }
      case State::SAW_PRINTABLE: {
        if (cur_has_child()) next_item();
        if (cur_non_empty() && prev_state != State::SAW_PRINTABLE) next_item();
        append_char();
        break;
      }
      }
      prev_state = state;
      i += 1;
    }
  exit_loop:
    (void)0;
    return root;
  error_parsing:
    return NULL;
  }
};

static inline bool parse_decimal_int(char const *str, size_t len, int32_t *result) {
  int32_t  final = 0;
  int32_t  pow   = 1;
  int32_t  sign  = 1;
  uint32_t i     = 0;
  // parsing in reverse order
  for (; i < len; ++i) {
    switch (str[len - 1 - i]) {
    case '0': break;
    case '1': final += 1 * pow; break;
    case '2': final += 2 * pow; break;
    case '3': final += 3 * pow; break;
    case '4': final += 4 * pow; break;
    case '5': final += 5 * pow; break;
    case '6': final += 6 * pow; break;
    case '7': final += 7 * pow; break;
    case '8': final += 8 * pow; break;
    case '9': final += 9 * pow; break;
    // it's ok to have '-'/'+' as the first char in a string
    case '-': {
      if (i == len - 1)
        sign = -1;
      else
        return false;
      break;
    }
    case '+': {
      if (i == len - 1)
        sign = 1;
      else
        return false;
      break;
    }
    default: return false;
    }
    pow *= 10;
  }
  *result = sign * final;
  return true;
}

static inline bool parse_float(char const *str, size_t len, float *result) {
  float    final = 0.0f;
  uint32_t i     = 0;
  float    sign  = 1.0f;
  if (str[0] == '-') {
    sign = -1.0f;
    i    = 1;
  }
  for (; i < len; ++i) {
    if (str[i] == '.') break;
    switch (str[i]) {
    case '0': final = final * 10.0f; break;
    case '1': final = final * 10.0f + 1.0f; break;
    case '2': final = final * 10.0f + 2.0f; break;
    case '3': final = final * 10.0f + 3.0f; break;
    case '4': final = final * 10.0f + 4.0f; break;
    case '5': final = final * 10.0f + 5.0f; break;
    case '6': final = final * 10.0f + 6.0f; break;
    case '7': final = final * 10.0f + 7.0f; break;
    case '8': final = final * 10.0f + 8.0f; break;
    case '9': final = final * 10.0f + 9.0f; break;
    default: return false;
    }
  }
  i++;
  float pow = 1.0e-1f;
  for (; i < len; ++i) {
    switch (str[i]) {
    case '0': break;
    case '1': final += 1.0f * pow; break;
    case '2': final += 2.0f * pow; break;
    case '3': final += 3.0f * pow; break;
    case '4': final += 4.0f * pow; break;
    case '5': final += 5.0f * pow; break;
    case '6': final += 6.0f * pow; break;
    case '7': final += 7.0f * pow; break;
    case '8': final += 8.0f * pow; break;
    case '9': final += 9.0f * pow; break;
    default: return false;
    }
    pow *= 1.0e-1f;
  }
  *result = sign * final;
  return true;
}

#define LOOKUP_FN(name)                                                                            \
  name = module->getFunction(#name);                                                               \
  ASSERT_ALWAYS(name != NULL);

#define ALLOC_VAL() (Value *)alloc_value()

#define ASSERT_EVAL(x)                                                                             \
  do {                                                                                             \
    if (!(x)) {                                                                                    \
      set_error();                                                                                 \
      state->push_error(#x);                                                                       \
      abort();                                                                                     \
      return NULL;                                                                                 \
    }                                                                                              \
  } while (0)
#define CHECK_ERROR()                                                                              \
  do {                                                                                             \
    if (is_error()) {                                                                              \
      abort();                                                                                     \
      return NULL;                                                                                 \
    }                                                                                              \
  } while (0)
#define CALL_EVAL(x)                                                                               \
  eval_unwrap(x);                                                                                  \
  CHECK_ERROR()
#define ASSERT_SMB(x) ASSERT_EVAL(x != NULL && x->type == (i32)Value::Value_t::SYMBOL);
#define ASSERT_I32(x) ASSERT_EVAL(x != NULL && x->type == (i32)Value::Value_t::I32);
#define ASSERT_F32(x) ASSERT_EVAL(x != NULL && x->type == (i32)Value::Value_t::F32);
#define ASSERT_ANY(x) ASSERT_EVAL(x != NULL && x->type == (i32)Value::Value_t::ANY);

#define EVAL_SMB(res, id)                                                                          \
  Value *res = eval_unwrap(l->get(id));                                                            \
  ASSERT_SMB(res)
#define EVAL_I32(res, id)                                                                          \
  Value *res = eval_unwrap(l->get(id));                                                            \
  ASSERT_I32(res)
#define EVAL_F32(res, id)                                                                          \
  Value *res = eval_unwrap(l->get(id));                                                            \
  ASSERT_F32(res)
#define EVAL_ANY(res, id)                                                                          \
  Value *res = eval_unwrap(l->get(id));                                                            \
  ASSERT_ANY(res)

struct Value {
  enum class Value_t : i32 { UNKNOWN = 0, I32, F32, SYMBOL, BINDING, LAMBDA, SCOPE, MODE, ANY };
  i32 type;
  i32 any_type;
  union {
    string_ref str;
    f32        f;
    i32        i;
    List *     list;
    void *     any;
  };
  void ATTR_USED dump() {
    fprintf(stdout, "Value; {\n");
    switch (type) {
    case (i32)Value_t::I32: {
      fprintf(stdout, "  i32: %i\n", i);
      break;
    }
    case (i32)Value_t::F32: {
      fprintf(stdout, "  f32: %f\n", f);
      break;
    }
    case (i32)Value_t::SYMBOL: {
      fprintf(stdout, "  sym: %.*s\n", STRF(str));
      break;
    }
    case (i32)Value_t::BINDING: {
      fprintf(stdout, "  bnd:\n");
      list->dump(4);
      break;
    }
    case (i32)Value_t::LAMBDA: {
      fprintf(stdout, "  lmb:\n");
      list->dump(4);
      break;
    }
    case (i32)Value_t::SCOPE: {
      fprintf(stdout, "  scp\n");
      break;
    }
    case (i32)Value_t::ANY: {
      fprintf(stdout, "  any\n");
      break;
    }
    case (i32)Value_t::MODE: {
      fprintf(stdout, "  mod\n");
      break;
    }
    default: UNIMPLEMENTED;
    }
    fprintf(stdout, "}\n");
    fflush(stdout);
  }
};

struct Symbol_Table {
  struct Symbol {
    string_ref name;
    Value *    val;
  };
  struct Symbol_Hash_Table {
    using Table_t = Hash_Table<string_ref, Value *, Default_Allocator, 0x10, 0x10>;
    Table_t            table;
    Symbol_Hash_Table *prev;
    void               init() {
      table.init();
      prev = NULL;
    }
    void release() {
      table.release();
      prev = NULL;
    }
  };
  Pool<Symbol_Hash_Table> table_storage;
  Symbol_Hash_Table *     head;
  Symbol_Hash_Table *     tail;

  void init() {
    table_storage = Pool<Symbol_Hash_Table>::create(0x400);
    head          = table_storage.alloc(1);
    head->init();
    tail = head;
  }
  void release() {
    Symbol_Hash_Table *cur = tail;
    while (cur != NULL) {
      Symbol_Hash_Table *prev = cur->prev;
      cur->release();
      cur = prev;
    }
    table_storage.release();
  }
  Value *lookup_value(string_ref name) {
    Symbol_Hash_Table *cur = tail;
    while (cur != NULL) {
      if (Value **val = cur->table.get_or_null(name)) return *val;
      cur = cur->prev;
    }
    return NULL;
  }
  Value *lookup_value(string_ref name, void *scope) {
    Symbol_Hash_Table *cur = (Symbol_Hash_Table *)scope;
    while (cur != NULL) {
      if (Value **val = cur->table.get_or_null(name)) return *val;
      cur = cur->prev;
    }
    return NULL;
  }
  void *get_scope() { return (void *)tail; }
  void  set_scope(void *scope) { tail = (Symbol_Hash_Table *)scope; }
  void  enter_scope() {
    Symbol_Hash_Table *new_table = table_storage.alloc(1);
    new_table->init();
    new_table->prev = tail;
    tail            = new_table;
  }
  void exit_scope() {
    Symbol_Hash_Table *new_tail = tail->prev;
    ASSERT_DEBUG(new_tail != NULL);
    tail->release();
    table_storage.pop();
    tail = new_tail;
  }
  void ATTR_USED dump() {
    Symbol_Hash_Table *cur = tail;
    while (cur != NULL) {
      fprintf(stdout, "--------new-table\n");
      cur->table.iter([&](Symbol_Hash_Table::Table_t::Pair_t const &item) {
        fprintf(stdout, "symbol(\"%.*s\"):\n", STRF(item.key));
        item.value->dump();
      });
      cur = cur->prev;
    }
  }
  void add_symbol(string_ref name, Value *val) { tail->table.insert(name, val); }
};

//////////////////
// Global state //
//////////////////
struct Evaluator_State {
  Pool<char>   string_storage;
  Pool<List>   list_storage;
  Pool<Value>  value_storage;
  Symbol_Table symbol_table;
  bool         eval_error = false;

  void init() {
    string_storage = Pool<char>::create((1 << 20));
    list_storage   = Pool<List>::create((1 << 20));
    value_storage  = Pool<Value>::create((1 << 20));
    symbol_table.init();
  }

  void release() {
    string_storage.release();
    list_storage.release();
    value_storage.release();
    symbol_table.release();
  }

  Value *alloc_value() { return value_storage.alloc_zero(1); }

  string_ref move_cstr(string_ref old) {
    char *     new_ptr = string_storage.put(old.ptr, old.len + 1);
    string_ref new_ref = string_ref{.ptr = new_ptr, .len = old.len};
    new_ptr[old.len]   = '\0';
    return new_ref;
  }

  void push_warning(char const *fmt, ...) {
    fprintf(stdout, "[WARNING] ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
  }

  void push_error(char const *fmt, ...) {
    fprintf(stdout, "[ERROR] ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);
  }
};
//////////////////
void global_set_evaluation_error();

struct Match {
  Value *val;
  bool   match;
  Match(Value *val) : val(val), match(true) {}
  Match(Value *val, bool match) : val(val), match(match) {}
  Value *unwrap() {
    if (!match) {
      global_set_evaluation_error();
      return NULL;
    }
    return val;
  }
};

struct IEvaluator {
  Evaluator_State *     state        = NULL;
  IEvaluator *          prev         = NULL;
  virtual Match         eval(List *) = 0;
  virtual void          release()    = 0;
  static IEvaluator *   get_head();
  static void           set_head(IEvaluator *);
  static IEvaluator *   create_mode(string_ref name);
  static Match          global_eval(List *l) { return get_head()->eval(l); }
  Value *               eval_unwrap(List *l) { return global_eval(l).unwrap(); }
  Pair<Value *, List *> eval_and_next_arg(List *l) {
    Value *a = eval_unwrap(l);
    if (a != NULL && a->type == (i32)Value::Value_t::BINDING) {
      List *next = l->next;
      if (next == NULL) next = a->list->next;
      a = eval_unwrap(a->list);
      return make_pair(a, next);
    } else {
      return make_pair(a, l->next);
    }
  }
  Value *eval_args(List *arg) {
    List * cur  = arg;
    Value *last = NULL;
    while (cur != NULL) {
      auto p = eval_and_next_arg(cur);
      cur    = p.second;
      last   = p.first;
    }
    return last;
  }
  template <typename V> void eval_args_and_collect(List *l, V &values) {
    while (true) {
      auto   p = eval_and_next_arg(l);
      Value *a = p.first;
      values.push(a);
      l = p.second;
      if (l == NULL) break;
    }
  }
  Value *    alloc_value() { return state->alloc_value(); }
  string_ref move_cstr(string_ref old) { return state->move_cstr(old); }
  void       set_error() { state->eval_error = true; }
  bool       is_error() { return state->eval_error; }
};

struct Default_Evaluator : public IEvaluator {
  //  SmallArray<IEvaluator *, 8> mods;

  void init() {
    //  mods.init();
  }

  void release() override {
    //  mods.release();
  }
  Match eval(List *l) override {
    if (l == NULL) return NULL;
    //    ito(mods.size) {
    //      Match match = mods[i]->eval(l);
    //      CHECK_ERROR();
    //      if (match.match) return match;
    //    }
    TMP_STORAGE_SCOPE;
    if (l->child != NULL) {
      ASSERT_EVAL(!l->nonempty());
      return global_eval(l->child);
    } else if (l->nonempty()) {
      i32  imm32;
      f32  immf32;
      bool is_imm32  = parse_decimal_int(l->symbol.ptr, l->symbol.len, &imm32);
      bool is_immf32 = parse_float(l->symbol.ptr, l->symbol.len, &immf32);
      if (is_imm32) {
        Value *new_val = ALLOC_VAL();
        new_val->i     = imm32;
        new_val->type  = (i32)Value::Value_t::I32;
        return new_val;
      } else if (is_immf32) {
        Value *new_val = ALLOC_VAL();
        new_val->f     = immf32;
        new_val->type  = (i32)Value::Value_t::F32;
        return new_val;
      } else if (l->cmp_symbol("for-range")) {
        List *name_l = l->next;
        ASSERT_EVAL(name_l->nonempty());
        string_ref name = name_l->symbol;
        Value *    lb   = CALL_EVAL(l->get(2));
        ASSERT_EVAL(lb != NULL && lb->type == (i32)Value::Value_t::I32);
        Value *ub = CALL_EVAL(l->get(3));
        ASSERT_EVAL(ub != NULL && ub->type == (i32)Value::Value_t::I32);
        Value *new_val = ALLOC_VAL();
        new_val->i     = 0;
        new_val->type  = (i32)Value::Value_t::I32;
        for (i32 i = lb->i; i < ub->i; i++) {
          state->symbol_table.enter_scope();
          new_val->i = i;
          state->symbol_table.add_symbol(name, new_val);
          defer(state->symbol_table.exit_scope());
          eval_args(l->get(4));
        }
        return NULL;
      } else if (l->cmp_symbol("for-items")) {
        Value *name = CALL_EVAL(l->next);
        ASSERT_EVAL(name->type == (i32)Value::Value_t::SYMBOL);
        SmallArray<Value *, 8> items;
        items.init();
        defer(items.release());
        eval_args_and_collect(l->next->next->child, items);
        ito(items.size) {
          state->symbol_table.enter_scope();
          state->symbol_table.add_symbol(name->str, items[i]);
          defer(state->symbol_table.exit_scope());
          eval_args(l->get(3));
        }
        return NULL;
      } else if (l->cmp_symbol("if")) {
        EVAL_I32(cond, 1);
        state->symbol_table.enter_scope();
        defer(state->symbol_table.exit_scope());
        if (cond->i != 0) {
          Value *val = CALL_EVAL(l->get(2));
          return val;
        } else {
          Value *val = CALL_EVAL(l->get(3));
          return val;
        }
      } else if (l->cmp_symbol("add-mode")) {
        EVAL_SMB(name, 1);
        state->symbol_table.enter_scope();
        defer(state->symbol_table.exit_scope());
        IEvaluator *mode = IEvaluator::create_mode(name->str);
        ASSERT_EVAL(mode != NULL);
        IEvaluator *old_head = IEvaluator::get_head();
        IEvaluator::set_head(mode);
        eval_args(l->get(2));
        IEvaluator::set_head(old_head);
        return NULL;
      } else if (l->cmp_symbol("lambda")) {
        Value *new_val = ALLOC_VAL();
        new_val->list  = l->next;
        new_val->type  = (i32)Value::Value_t::LAMBDA;
        return new_val;
      } else if (l->cmp_symbol("scope")) {
        state->symbol_table.enter_scope();
        defer(state->symbol_table.exit_scope());
        return eval_args(l->next);
      } else if (l->cmp_symbol("add")) {
        auto   p   = eval_and_next_arg(l->get(1));
        Value *op1 = p.first;
        ASSERT_EVAL(op1 != NULL);
        Value *op2 = CALL_EVAL(p.second);
        ASSERT_EVAL(op2 != NULL);
        ASSERT_EVAL(op1->type == op2->type);
        if (op1->type == (i32)Value::Value_t::I32) {
          Value *new_val = ALLOC_VAL();
          new_val->i     = op1->i + op2->i;
          new_val->type  = (i32)Value::Value_t::I32;
          return new_val;
        } else if (op1->type == (i32)Value::Value_t::F32) {
          Value *new_val = ALLOC_VAL();
          new_val->f     = op1->f + op2->f;
          new_val->type  = (i32)Value::Value_t::F32;
          return new_val;
        } else {
          ASSERT_EVAL(false && "add: unsopported operand types");
        }
        return NULL;
      } else if (l->cmp_symbol("sub")) {
        SmallArray<Value *, 2> args;
        args.init();
        defer(args.release());
        eval_args_and_collect(l->next, args);
        ASSERT_EVAL(args.size == 2);
        Value *op1 = args[0];
        ASSERT_EVAL(op1 != NULL);
        Value *op2 = args[1];
        ASSERT_EVAL(op2 != NULL);
        ASSERT_EVAL(op1->type == op2->type);
        if (op1->type == (i32)Value::Value_t::I32) {
          Value *new_val = ALLOC_VAL();
          new_val->i     = op1->i - op2->i;
          new_val->type  = (i32)Value::Value_t::I32;
          return new_val;
        } else if (op1->type == (i32)Value::Value_t::F32) {
          Value *new_val = ALLOC_VAL();
          new_val->f     = op1->f - op2->f;
          new_val->type  = (i32)Value::Value_t::F32;
          return new_val;
        } else {
          ASSERT_EVAL(false && "sub: unsopported operand types");
        }
        return NULL;
      } else if (l->cmp_symbol("mul")) {
        SmallArray<Value *, 2> args;
        args.init();
        defer(args.release());
        eval_args_and_collect(l->next, args);
        ASSERT_EVAL(args.size == 2);
        Value *op1 = args[0];
        ASSERT_EVAL(op1 != NULL);
        Value *op2 = args[1];
        ASSERT_EVAL(op2 != NULL);
        ASSERT_EVAL(op1->type == op2->type);
        if (op1->type == (i32)Value::Value_t::I32) {
          Value *new_val = ALLOC_VAL();
          new_val->i     = op1->i * op2->i;
          new_val->type  = (i32)Value::Value_t::I32;
          return new_val;
        } else if (op1->type == (i32)Value::Value_t::F32) {
          Value *new_val = ALLOC_VAL();
          new_val->f     = op1->f * op2->f;
          new_val->type  = (i32)Value::Value_t::F32;
          return new_val;
        } else {
          ASSERT_EVAL(false && "mul: unsopported operand types");
        }
        return NULL;
      } else if (l->cmp_symbol("cmp")) {
        List *                 mode = l->next;
        SmallArray<Value *, 2> args;
        args.init();
        defer(args.release());
        eval_args_and_collect(mode->next, args);
        ASSERT_EVAL(args.size == 2);
        Value *op1 = args[0];
        ASSERT_EVAL(op1 != NULL);
        Value *op2 = args[1];
        ASSERT_EVAL(op2 != NULL);
        ASSERT_EVAL(op1->type == op2->type);
        if (mode->cmp_symbol("lt")) {
          if (op1->type == (i32)Value::Value_t::I32) {
            Value *new_val = ALLOC_VAL();
            new_val->i     = op1->i < op2->i ? 1 : 0;
            new_val->type  = (i32)Value::Value_t::I32;
            return new_val;
          } else if (op1->type == (i32)Value::Value_t::F32) {
            Value *new_val = ALLOC_VAL();
            new_val->i     = op1->f < op2->f ? 1 : 0;
            new_val->type  = (i32)Value::Value_t::I32;
            return new_val;
          } else {
            ASSERT_EVAL(false && "cmp: unsopported operand types");
          }
        } else if (mode->cmp_symbol("eq")) {
          if (op1->type == (i32)Value::Value_t::I32) {
            Value *new_val = ALLOC_VAL();
            new_val->i     = op1->i == op2->i ? 1 : 0;
            new_val->type  = (i32)Value::Value_t::I32;
            return new_val;
          } else if (op1->type == (i32)Value::Value_t::F32) {
            Value *new_val = ALLOC_VAL();
            new_val->i     = op1->f == op2->f ? 1 : 0;
            new_val->type  = (i32)Value::Value_t::I32;
            return new_val;
          } else {
            ASSERT_EVAL(false && "cmp: unsopported operand types");
          }
        } else {
          ASSERT_EVAL(false && "cmp: unsopported op");
        }
        return NULL;
      } else if (l->cmp_symbol("let")) {
        List *name = l->next;
        ASSERT_EVAL(name->nonempty());
        Value *val = CALL_EVAL(l->get(2));
        state->symbol_table.add_symbol(name->symbol, val);
        return val;
      } else if (l->cmp_symbol("get-scope")) {
        Value *new_val = ALLOC_VAL();
        new_val->any   = state->symbol_table.get_scope();
        new_val->type  = (i32)Value::Value_t::SCOPE;
        return new_val;
      } else if (l->cmp_symbol("set-scope")) {
        Value *val = CALL_EVAL(l->get(1));
        ASSERT_EVAL(val != NULL && val->type == (i32)Value::Value_t::SCOPE);
        void *old_scope = state->symbol_table.get_scope();
        state->symbol_table.set_scope(val->any);
        state->symbol_table.enter_scope();
        defer({
          state->symbol_table.exit_scope();
          state->symbol_table.set_scope(old_scope);
        });
        { // Preserve list
          List *cur = l->get(2)->child;
          while (cur != NULL) {
            if (cur->nonempty()) {
              state->symbol_table.add_symbol(
                  cur->symbol, state->symbol_table.lookup_value(cur->symbol, old_scope));
            }
            cur = cur->next;
          }
        }
        return eval_args(l->get(3));
      } else if (l->cmp_symbol("get-mode")) {
        Value *new_val = ALLOC_VAL();
        new_val->any   = get_head();
        new_val->type  = (i32)Value::Value_t::MODE;
        return new_val;
      } else if (l->cmp_symbol("set-mode")) {
        Value *val = CALL_EVAL(l->get(1));
        ASSERT_EVAL(val != NULL && val->type == (i32)Value::Value_t::MODE);
        IEvaluator *old_mode = get_head();
        set_head((IEvaluator *)val->any);
        defer(set_head(old_mode););
        return eval_args(l->get(2));
      } else if (l->cmp_symbol("quote")) {
        Value *new_val = ALLOC_VAL();
        new_val->list  = l->next;
        new_val->type  = (i32)Value::Value_t::BINDING;
        return new_val;
      } else if (l->cmp_symbol("deref")) {
        return state->symbol_table.lookup_value(l->next->symbol);
      } else if (l->cmp_symbol("unbind")) {
        ASSERT_EVAL(l->next->nonempty());
        Value *sym = state->symbol_table.lookup_value(l->next->symbol);
        ASSERT_EVAL(sym != NULL && sym->type == (i32)Value::Value_t::BINDING);
        return global_eval(sym->list);
      } else if (l->cmp_symbol("unquote")) {
        ASSERT_EVAL(l->next->nonempty());
        Value *sym = state->symbol_table.lookup_value(l->next->symbol);
        ASSERT_EVAL(sym != NULL && sym->type == (i32)Value::Value_t::BINDING);
        ASSERT_EVAL(sym->list->nonempty());
        Value *new_val = ALLOC_VAL();
        new_val->str   = sym->list->symbol;
        new_val->type  = (i32)Value::Value_t::SYMBOL;
        return new_val;
      } else if (l->cmp_symbol("nil")) {
        return NULL;
      } else if (l->cmp_symbol("print")) {
        EVAL_SMB(str, 1);
        fprintf(stdout, "%.*s\n", STRF(str->str));
        return NULL;
      } else if (l->cmp_symbol("format")) {
        // state->symbol_table.dump();
        SmallArray<Value *, 4> args;
        args.init();
        defer({ args.release(); });
        eval_args_and_collect(l->next, args);
        Value *fmt    = args[0];
        u32    cur_id = 1;
        {
          char *      tmp_buf = (char *)tl_alloc_tmp(0x100);
          u32         cursor  = 0;
          char const *c       = fmt->str.ptr;
          char const *end     = fmt->str.ptr + fmt->str.len;
          while (c != end) {
            if (c[0] == '%') {
              if (c + 1 == end) {
                ASSERT_EVAL(false && "[format] Format string ends with %%");
              }
              if (cur_id == args.size) {
                ASSERT_EVAL(false && "[format] Not enough arguments");
              } else {
                i32    num_chars = 0;
                Value *val       = args[cur_id];
                if (c[1] == 'i') {
                  ASSERT_EVAL(val != NULL && val->type == (i32)Value::Value_t::I32);
                  num_chars = sprintf(tmp_buf + cursor, "%i", val->i);
                } else if (c[1] == 'f') {
                  ASSERT_EVAL(val != NULL && val->type == (i32)Value::Value_t::F32);
                  num_chars = sprintf(tmp_buf + cursor, "%f", val->f);
                } else if (c[1] == 's') {
                  ASSERT_EVAL(val != NULL && val->type == (i32)Value::Value_t::SYMBOL);
                  num_chars = sprintf(tmp_buf + cursor, "%.*s", (i32)val->str.len, val->str.ptr);
                } else {
                  ASSERT_EVAL(false && "[format]  Unknown format");
                }
                if (num_chars < 0) {
                  ASSERT_EVAL(false && "[format] Blimey!");
                }
                if (num_chars > 0x100) {
                  ASSERT_EVAL(false && "[format] Format buffer overflow!");
                }
                cursor += num_chars;
              }
              cur_id += 1;
              c += 1;
            } else {
              tmp_buf[cursor++] = c[0];
            }
            c += 1;
          }
          tmp_buf[cursor] = '\0';
          Value *new_val  = ALLOC_VAL();
          new_val->str    = move_cstr(stref_s(tmp_buf));
          new_val->type   = (i32)Value::Value_t::SYMBOL;
          return new_val;
        }
      } else {
        ASSERT_EVAL(l->nonempty());
        Value *sym = state->symbol_table.lookup_value(l->symbol);
        if (sym != NULL) {
          if (sym->type == (i32)Value::Value_t::LAMBDA) {
            ASSERT_EVAL(sym->list->child != NULL);
            List *lambda   = sym->list; // Try to evaluate
            List *arg_name = lambda->child;
            List *arg_val  = l->next;
            state->symbol_table.enter_scope();
            defer(state->symbol_table.exit_scope());
            bool saw_vararg = false;
            while (arg_name != NULL && arg_name->nonempty()) { // Bind arguments
              ASSERT_EVAL(!saw_vararg && "vararg must be the last argument");
              ASSERT_EVAL(arg_val != NULL);
              ASSERT_EVAL(arg_name->nonempty());
              if (arg_name->cmp_symbol("...")) {
                Value *new_val = ALLOC_VAL();
                new_val->list  = arg_val;
                new_val->type  = (i32)Value::Value_t::BINDING;
                state->symbol_table.add_symbol(arg_name->symbol, new_val);
                saw_vararg = true;
              } else {
                Value *val = CALL_EVAL(arg_val);
                state->symbol_table.add_symbol(arg_name->symbol, val);
              }
              arg_name = arg_name->next;
              arg_val  = arg_val->next;
            }
            return eval_args(lambda->next);
          } else if (sym->type == (i32)Value::Value_t::BINDING) {
            //            Value *val = CALL_EVAL(sym->list);
            Value *val = sym;
            return val;
          }
          return sym;
        }
        Value *new_val = ALLOC_VAL();
        new_val->str   = l->symbol;
        new_val->type  = (i32)Value::Value_t::SYMBOL;
        return new_val;
      }
    }
    TRAP;
  }
};

#if 1

#define UNWRAP_LLVM_VALUE(x) (llvm::Value *)x->any
#define UNWRAP_LLVM_TYPE(x) (llvm::Type *)x->any
#define CALL_LLVM_EVAL(x)                                                                          \
  llvm_eval(x);                                                                                    \
  CHECK_ERROR()
#define EVAL_LLVM(res, x)                                                                          \
  auto res = llvm_eval(x);                                                                         \
  CHECK_ERROR()
#define CHK_ERR(x)                                                                                 \
  x;                                                                                               \
  CHECK_ERROR()

struct LLVM_Evaluator : public IEvaluator {
  enum class LLVM_Value_t : i32 { UNKNOWN = 0, VALUE, TYPE };
  Value *wrap_value(llvm::Value *val) {
    Value *new_val    = ALLOC_VAL();
    new_val->any      = val;
    new_val->type     = (i32)Value::Value_t::ANY;
    new_val->any_type = (i32)LLVM_Value_t::VALUE;
    return new_val;
  }
  Value *wrap_type(llvm::Type *type) {
    Value *new_val    = ALLOC_VAL();
    new_val->any      = type;
    new_val->type     = (i32)Value::Value_t::ANY;
    new_val->any_type = (i32)LLVM_Value_t::TYPE;
    return new_val;
  }
  ///////////////
  // llvm-mode //
  ///////////////
  std::unique_ptr<llvm::LLVMContext> context;
  llvm::LLVMContext &                c;
  using LLVM_IR_Builder_t = llvm::IRBuilder<llvm::NoFolder>;

  // Varying
  std::unique_ptr<llvm::Module>                    module;
  llvm::Function *                                 ll_printf;
  llvm::Function *                                 ll_assert;
  llvm::Function *                                 ll_debug_assert;
  llvm::Function *                                 cur_fun   = NULL;
  llvm::BasicBlock *                               cur_bb    = NULL;
  llvm::BasicBlock *                               alloca_bb = NULL;
  std::unique_ptr<llvm::IRBuilder<llvm::NoFolder>> llvm_builder;
  i32                                              target_bits = 64;
  bool                                             target_avx2 = true;

  struct Deferred_Branch {
    llvm::Value *     cond         = NULL;
    string_ref        true_target  = {};
    string_ref        false_target = {};
    llvm::BasicBlock *src          = NULL;
  };
  Array<Deferred_Branch>                         deferred_branches;
  Hash_Table<string_ref, llvm::GlobalVariable *> global_strings;
  Hash_Table<string_ref, llvm::BasicBlock *>     labels;
  //////////////

  void init() {
    labels.init();
    deferred_branches.init();
    global_strings.init();
    struct_type_table = Pool<Struct_Type>::create((1 << 10));
  }

  void release() override {
    labels.release();
    deferred_branches.release();
    global_strings.release();
    context.release();
    struct_type_table.release();
  }

  LLVM_Evaluator() : context(new llvm::LLVMContext()), c(*context) {}

  llvm::Value *lookup_string(string_ref str) {
    if (global_strings.contains(str))
      return llvm_builder->CreateBitCast(global_strings.get(str), llvm::Type::getInt8PtrTy(c));

    llvm::Constant *msg =
        llvm::ConstantDataArray::getString(c, llvm::StringRef(str.ptr, str.len), true);
    llvm::GlobalVariable *msg_glob = new llvm::GlobalVariable(
        *module, msg->getType(), true, llvm::GlobalValue::InternalLinkage, msg);
    msg_glob->setAlignment(llvm::MaybeAlign(32));
    global_strings.insert(str, msg_glob);
    return llvm_builder->CreateBitCast(msg_glob, llvm::Type::getInt8PtrTy(c));
  }

  struct Struct_Type {
    string_ref *members;
    u32         member_count;
    llvm::Type *ty;
  };
  Pool<Struct_Type> struct_type_table;
  void              add_struct(Struct_Type struct_ty) { struct_type_table.push(struct_ty); }
  u32               lookup_struct_member(llvm::Type *ty, string_ref member_name) {
    ito(struct_type_table.cursor) {
      u32 index = struct_type_table.cursor - 1 - i;
      if (struct_type_table.at(index)->ty == ty) {
        Struct_Type sty = *struct_type_table.at(index);
        jto(sty.member_count) {
          if (sty.members[j] == member_name) return j;
        }
        return -1;
      }
    }
    return -1;
  }

  auto llvm_get_constant_i32(u32 a) {
    return llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(*context), a);
  }
  auto llvm_get_constant_f32(f32 a) {
    return llvm::ConstantFP::get(llvm::IntegerType::getFloatTy(*context), (f64)a);
  }
  auto llvm_get_constant_i64(u64 a) {
    return llvm::ConstantInt::get(llvm::IntegerType::getInt64Ty(*context), a);
  }
  i32 parse_int(List *l) {
    int32_t i = 0;
    if (l == NULL || !l->nonempty() || !parse_decimal_int(l->symbol.ptr, l->symbol.len, &i)) {
      set_error();
      return 0;
    }
    return i;
  }
  llvm::Type *parse_type(List *l) {
    ASSERT_EVAL(l != NULL);
    if (l->nonempty() == false) {
      ASSERT_EVAL(l->child != NULL);
      return parse_type(l->child);
    }
    ASSERT_EVAL(l->nonempty());
    Value *     prev_val = state->symbol_table.lookup_value(l->symbol);
    llvm::Type *prev     = NULL;
    if (prev_val != NULL && prev_val->type == (i32)Value::Value_t::ANY &&
        prev_val->any_type == (i32)LLVM_Value_t::TYPE) {
      prev = (llvm::Type *)prev_val->any;
    }
    if (prev != NULL) return prev;
    if (l->cmp_symbol("intptr_t")) { // Platform specific
      if (target_bits == 64) {
        return llvm::Type::getInt64Ty(c);
      } else if (target_bits == 32) {
        return llvm::Type::getInt32Ty(c);
      } else {
        UNIMPLEMENTED;
      }
    } else if (l->cmp_symbol("typeof")) {
      EVAL_LLVM(val, l->next);
      return val->getType();
    } else if (l->cmp_symbol("i32")) {
      return llvm::Type::getInt32Ty(c);
    } else if (l->cmp_symbol("i64")) {
      return llvm::Type::getInt64Ty(c);
    } else if (l->cmp_symbol("f32")) {
      return llvm::Type::getFloatTy(c);
    } else if (l->cmp_symbol("i16")) {
      return llvm::Type::getInt16Ty(c);
    } else if (l->cmp_symbol("i8")) {
      return llvm::Type::getInt8Ty(c);
    } else if (l->cmp_symbol("i1")) {
      return llvm::Type::getInt1Ty(c);
    } else if (l->cmp_symbol("pointer")) {
      return llvm::PointerType::get(parse_type(l->next), 0);
    } else if (l->cmp_symbol("vector")) {
      Value *val = eval_unwrap(l->next->next);
      CHECK_ERROR();
      return llvm::VectorType::get(parse_type(l->next), val->i);
    } else if (l->cmp_symbol("array")) {
      return llvm::ArrayType::get(parse_type(l->next), parse_int(l->next->next));
    } else if (l->cmp_symbol("struct")) {
      llvm::SmallVector<llvm::Type *, 4> members;
      llvm::SmallVector<string_ref, 4>   names;
      List *                             cur = l->next;

      while (cur != NULL) {
        List *member_type = cur->child->get(0);
        ASSERT_EVAL(member_type != NULL && member_type->next != NULL);
        string_ref  name = cur->child->get(1)->symbol;
        llvm::Type *ty   = parse_type(member_type);
        CHECK_ERROR();
        names.push_back(name);
        members.push_back(ty);
        cur = cur->next;
      }
      // copy names to the string storage to simplify memory management
      string_ref *name_storage =
          (string_ref *)state->string_storage.alloc(sizeof(string_ref) * names.size());
      ito(names.size()) { name_storage[i] = move_cstr(names[i]); }
      Struct_Type sty;
      sty.members      = name_storage;
      sty.member_count = names.size();
      sty.ty           = llvm::StructType::create(c, members);
      add_struct(sty);
      return sty.ty;
    } else {
      return NULL;
    }
  }

  llvm::Value *make_vector(llvm::Type *type, List *l) {
    llvm::SmallVector<List *, 8> args;
    {
      List *arg = l;
      while (arg != NULL) {
        args.push_back(arg);
        arg = arg->next;
      }
    }
    ASSERT_EVAL(args.size() > 1);
    llvm::Type * arr_ty = llvm::VectorType::get(type, args.size());
    llvm::Value *arr    = llvm::UndefValue::get(arr_ty);
    ito(args.size()) {
      EVAL_LLVM(val, args[i]);
      arr = llvm_builder->CreateInsertElement(arr, val, i);
    }
    return arr;
  }

  Match eval(List *l) override {
    ASSERT_EVAL(l != NULL);
    if (!l->nonempty()) {
      ASSERT_EVAL(l->child != NULL);
      return global_eval(l->child);
    }
    ASSERT_EVAL(l->nonempty());
    TMP_STORAGE_SCOPE;
    List **argv = (List **)tl_alloc_tmp(sizeof(List *));
    u32    argc = 0;
    {
      List *arg = l->next;
      while (arg != NULL) {
        argv[argc++] = arg;
        tl_alloc_tmp(sizeof(List *));
        arg = arg->next;
      }
    }
    //    i32  imm32;
    //    f32  immf32;
    //    bool is_imm32  = parse_decimal_int(l->symbol.ptr, l->symbol.len, &imm32);
    //    bool is_immf32 = parse_float(l->symbol.ptr, l->symbol.len, &immf32);
    //    if (is_imm32) {
    //      return wrap_value(llvm_get_constant_i32(imm32));
    //    } else if (is_immf32) {
    //      return wrap_value(llvm_get_constant_f32(immf32));
    //    } else
    if (l->cmp_symbol("fcmp")) {
      ASSERT_EVAL(argc == 3);
      llvm::FCmpInst::Predicate type = llvm::FCmpInst::FCMP_FALSE;
      if (argv[0]->cmp_symbol("eq")) {
        type = llvm::FCmpInst::FCMP_OEQ;
      } else if (argv[0]->cmp_symbol("lt")) {
        type = llvm::FCmpInst::FCMP_OLT;
      } else if (argv[0]->cmp_symbol("le")) {
        type = llvm::FCmpInst::FCMP_OLE;
      } else if (argv[0]->cmp_symbol("gt")) {
        type = llvm::FCmpInst::FCMP_OGT;
      } else if (argv[0]->cmp_symbol("ge")) {
        type = llvm::FCmpInst::FCMP_OGE;
      } else {
        ASSERT_EVAL(false && "Unimplemented");
      }
      EVAL_LLVM(val_0, argv[1]);
      EVAL_LLVM(val_1, argv[2]);
      return wrap_value(llvm_builder->CreateFCmp(type, val_0, val_1));
    } else if (l->cmp_symbol("icmp")) {
      ASSERT_EVAL(argc == 3);
      llvm::ICmpInst::Predicate type = llvm::ICmpInst::FCMP_FALSE;
      if (argv[0]->cmp_symbol("eq")) {
        type = llvm::FCmpInst::ICMP_EQ;
      } else if (argv[0]->cmp_symbol("slt")) {
        type = llvm::FCmpInst::ICMP_SLT;
      } else if (argv[0]->cmp_symbol("sle")) {
        type = llvm::FCmpInst::ICMP_SLE;
      } else if (argv[0]->cmp_symbol("sgt")) {
        type = llvm::FCmpInst::ICMP_SGT;
      } else if (argv[0]->cmp_symbol("sge")) {
        type = llvm::FCmpInst::ICMP_SGE;
      } else if (argv[0]->cmp_symbol("ult")) {
        type = llvm::FCmpInst::ICMP_ULT;
      } else if (argv[0]->cmp_symbol("ule")) {
        type = llvm::FCmpInst::ICMP_ULE;
      } else if (argv[0]->cmp_symbol("ugt")) {
        type = llvm::FCmpInst::ICMP_UGT;
      } else if (argv[0]->cmp_symbol("uge")) {
        type = llvm::FCmpInst::ICMP_UGE;
      } else {
        ASSERT_EVAL(false && "Unimplemented");
      }
      EVAL_LLVM(val_0, argv[1]);
      EVAL_LLVM(val_1, argv[2]);
      return wrap_value(llvm_builder->CreateICmp(type, val_0, val_1));
    } else
#define BINOP(mn, fn)                                                                              \
  if (l->cmp_symbol(mn)) {                                                                         \
    ASSERT_EVAL(argc == 2);                                                                        \
    EVAL_LLVM(val_0, argv[0]);                                                                     \
    EVAL_LLVM(val_1, argv[1]);                                                                     \
    return wrap_value(llvm_builder->fn(val_0, val_1));                                             \
  }
      // clang-format off
      BINOP("fadd", CreateFAdd)
      else
      BINOP("fsub", CreateFSub)
      else
      BINOP("fmul", CreateFMul)
      else
      BINOP("fdiv", CreateFDiv)
      else
      BINOP("iadd", CreateAdd)
      else
      BINOP("isub", CreateSub)
      else
      BINOP("sdiv", CreateSDiv)
      else
      BINOP("smul", CreateNSWMul)
      else
      BINOP("udiv", CreateUDiv)
      else
      BINOP("umod", CreateURem)
      else
      BINOP("umul", CreateNUWMul)
      else
      BINOP("and", CreateAnd)
      else
      BINOP("or", CreateOr)
      else
      BINOP("shl", CreateShl)
      else
      BINOP("shr", CreateLShr)
      else
     #undef BINOP
        // clang-format on
        if (l->cmp_symbol("load")) {
      ASSERT_EVAL(argc == 1);
      EVAL_LLVM(val, argv[0]);
      return wrap_value(llvm_builder->CreateLoad(val));
    }
    else if (l->cmp_symbol("ptrtoint")) {
      ASSERT_EVAL(argc == 1);
      EVAL_LLVM(val, argv[0]);
      if (target_bits == 32)
        return wrap_value(llvm_builder->CreatePtrToInt(val, llvm::Type::getInt32Ty(c)));
      else
        return wrap_value(llvm_builder->CreatePtrToInt(val, llvm::Type::getInt64Ty(c)));
    }
    else if (l->cmp_symbol("all")) {
      ASSERT_EVAL(argc == 1);
      EVAL_LLVM(val, argv[0]);
      ASSERT_EVAL(val->getType()->isVectorTy());
      llvm::VectorType *vt = llvm::dyn_cast<llvm::VectorType>(val->getType());
      ASSERT_EVAL(vt->getElementType() == llvm::Type::getInt1Ty(c));
      u32          cnt = vt->getElementCount().Min;
      llvm::Value *bc  = llvm_builder->CreateBitCast(val, llvm::Type::getIntNTy(c, cnt));
      llvm::Value *cmp =
          llvm_builder->CreateICmpEQ(bc, llvm::ConstantInt::get(c, llvm::APInt(cnt, ~0, false)));
      return wrap_value(cmp);
    }
    else if (l->cmp_symbol("any")) {
      ASSERT_EVAL(argc == 1);
      EVAL_LLVM(val, argv[0]);
      ASSERT_EVAL(val->getType()->isVectorTy());
      llvm::VectorType *vt = llvm::dyn_cast<llvm::VectorType>(val->getType());
      ASSERT_EVAL(vt->getElementType() == llvm::Type::getInt1Ty(c));
      u32          cnt = vt->getElementCount().Min;
      llvm::Value *bc  = llvm_builder->CreateBitCast(val, llvm::Type::getIntNTy(c, cnt));
      llvm::Value *cmp =
          llvm_builder->CreateICmpNE(bc, llvm::ConstantInt::get(c, llvm::APInt(cnt, 0, false)));
      return wrap_value(cmp);
    }
    else if (l->cmp_symbol("none")) {
      ASSERT_EVAL(argc == 1);
      EVAL_LLVM(val, argv[0]);
      ASSERT_EVAL(val->getType()->isVectorTy());
      llvm::VectorType *vt = llvm::dyn_cast<llvm::VectorType>(val->getType());
      ASSERT_EVAL(vt->getElementType() == llvm::Type::getInt1Ty(c));
      u32          cnt = vt->getElementCount().Min;
      llvm::Value *bc  = llvm_builder->CreateBitCast(val, llvm::Type::getIntNTy(c, cnt));
      llvm::Value *cmp =
          llvm_builder->CreateICmpEQ(bc, llvm::ConstantInt::get(c, llvm::APInt(cnt, 0, false)));
      return wrap_value(cmp);
    }
    else if (l->cmp_symbol("not")) {
      ASSERT_EVAL(argc == 1);
      EVAL_LLVM(val, argv[0]);
      llvm::Value *cmp = llvm_builder->CreateNot(val);
      return wrap_value(cmp);
    }
    else if (l->cmp_symbol("at")) {
      ASSERT_EVAL(argc > 1);
      llvm::SmallVector<llvm::Value *, 4> chain;
      ito(argc - 1) {
        llvm::Value *val = llvm_eval(argv[i + 1]);
        ASSERT_EVAL(val != NULL);
        CHECK_ERROR();
        chain.push_back(val);
        //        llvm_get_constant_i32(parse_int(argv[i + 1])));
        CHECK_ERROR();
      }
      EVAL_LLVM(val, argv[0]);
      return wrap_value(llvm_builder->CreateLoad(llvm_builder->CreateGEP(val, chain)));
    }
    else if (l->cmp_symbol("gep")) {
      ASSERT_EVAL(argc > 1);
      llvm::SmallVector<llvm::Value *, 4> chain;
      ito(argc - 1) {
        chain.push_back(llvm_get_constant_i32(parse_int(argv[i + 1])));
        CHECK_ERROR();
      }
      EVAL_LLVM(val, argv[0]);
      return wrap_value(llvm_builder->CreateGEP(val, chain));
    }
    else if (l->cmp_symbol("extract_element")) {
      ASSERT_EVAL(argc > 1);
      EVAL_LLVM(val, argv[0]);
      EVAL_I32(index, 2)
      return wrap_value(llvm_builder->CreateExtractElement(val, llvm_get_constant_i32(index->i)));
    }
    else if (l->cmp_symbol("insert_element")) {
      ASSERT_EVAL(argc > 1);
      EVAL_LLVM(val, argv[0]);
      EVAL_LLVM(val1, argv[1]);
      i32 i = parse_int(argv[2]);
      CHECK_ERROR();
      return wrap_value(llvm_builder->CreateInsertElement(val, val1, i));
    }
    else if (l->cmp_symbol("extract_value")) {
      ASSERT_EVAL(argc > 1);
      llvm::SmallVector<u32, 4> indxs;
      ito(argc - 1) {
        i32 in = parse_int(argv[i + 1]);
        CHECK_ERROR();
        indxs.push_back(in);
      }
      EVAL_LLVM(val, argv[0]);
      return wrap_value(llvm_builder->CreateExtractValue(val, indxs));
    }
    else if (l->cmp_symbol("insert_value")) {
      ASSERT_EVAL(argc > 1);
      llvm::SmallVector<u32, 4> indxs;
      ito(argc - 1) {
        i32 in = parse_int(argv[i + 2]);
        CHECK_ERROR();
        indxs.push_back(in);
      }
      EVAL_LLVM(val, argv[0]);
      EVAL_LLVM(val1, argv[1]);
      return wrap_value(llvm_builder->CreateInsertValue(val, val1, indxs));
    }
    else if (l->cmp_symbol("store")) {
      ASSERT_EVAL(argc == 2);
      EVAL_LLVM(val, argv[0]);
      EVAL_LLVM(val1, argv[1]);
      return wrap_value(llvm_builder->CreateStore(val, val1));
    }
    else if (l->cmp_symbol("bitcast")) {
      ASSERT_EVAL(argc == 2);
      EVAL_LLVM(val, argv[0]);
      llvm::Type *ty = parse_type(argv[1]);
      CHECK_ERROR();
      return wrap_value(llvm_builder->CreateBitCast(val, ty));
    }
    else if (l->cmp_symbol("trunc")) {
      ASSERT_EVAL(argc == 2);
      EVAL_LLVM(val, argv[0]);
      llvm::Type *ty = parse_type(argv[1]);
      CHECK_ERROR();
      return wrap_value(llvm_builder->CreateTrunc(val, ty));
    }
    else if (l->cmp_symbol("sext")) {
      ASSERT_EVAL(argc == 2);
      EVAL_LLVM(val, argv[0]);
      llvm::Type *ty = parse_type(argv[1]);
      CHECK_ERROR();
      return wrap_value(llvm_builder->CreateSExt(val, ty));
    }
    else if (l->cmp_symbol("zext")) {
      ASSERT_EVAL(argc == 2);
      EVAL_LLVM(val, argv[0]);
      llvm::Type *ty = parse_type(argv[1]);
      CHECK_ERROR();
      return wrap_value(llvm_builder->CreateZExt(val, ty));
    }
    else if (l->cmp_symbol("alloca")) {
      ASSERT_EVAL(argc == 1);
      //      Value *type_val = global_eval(argv[0]).unwrap();
      //      CHECK_ERROR();
      //      ASSERT_EVAL(type_val != NULL &&
      //                      type_val->type == (i32)Value::Value_t::ANY &&type_val->any_type =
      //                      (i32)LLVM_Value_t::TYPE);
      //      llvm::Type *type = CHK_ERR(parse_type((llvm::Type *)type_val->any));
      llvm::Type *type = CHK_ERR(parse_type(l->next));
      return wrap_value(llvm_builder->CreateAlloca(type));
    }
    else if (l->cmp_symbol("make_array")) {
      ASSERT_EVAL(argc > 1);
      llvm::Type * type   = CHK_ERR(parse_type(argv[0]));
      llvm::Type * arr_ty = llvm::ArrayType::get(type, argc - 1);
      llvm::Value *arr    = llvm::UndefValue::get(arr_ty);
      ito(argc - 1) {
        EVAL_LLVM(val, argv[1 + i]);
        arr = llvm_builder->CreateInsertValue(arr, val, i);
      }
      return wrap_value(arr);
    }
    else if (l->cmp_symbol("make_matrix")) {
      ASSERT_EVAL(argc > 1);
      llvm::Type *                        type = parse_type(argv[0]);
      llvm::SmallVector<llvm::Value *, 4> rows;
      ito(argc - 1) {
        List *       cur = argv[1 + i]->child;
        llvm::Value *vec = CHK_ERR(make_vector(type, cur));
        rows.push_back(vec);
      }
      llvm::Type * arr_ty  = llvm::ArrayType::get(rows[0]->getType(), rows.size());
      llvm::Value *arr     = llvm::UndefValue::get(arr_ty);
      ito(rows.size()) arr = llvm_builder->CreateInsertValue(arr, rows[i], i);
      return wrap_value(arr);
    }
    else if (l->cmp_symbol("make_vector")) {
      llvm::Value *vec = CHK_ERR(make_vector(parse_type(l->next), l->next->next));
      return wrap_value(vec);
    }
    //    else if (l->cmp_symbol("let")) {
    //      ASSERT_EVAL(argc == 2);
    //      string_ref   val_name = argv[0]->get_symbol();
    //      llvm::Value *val      = CALL_LLVM_EVAL(argv[1]);
    //      state->symbol_table.add_symbol(val_name, wrap_value(val));
    //      return NULL;
    //    }
    //    else if (l->cmp_symbol("def")) {
    //      ASSERT_EVAL(argc == 2);
    //      string_ref  val_name = argv[0]->get_symbol();
    //      llvm::Type *val      = CHK_ERR(parse_type(argv[1]));
    //      state->symbol_table.add_symbol(val_name, wrap_type(val));
    //      return NULL;
    //    }
    else if (l->cmp_symbol("format")) {
      ASSERT_EVAL(argc > 0);
      EVAL_LLVM(buf, argv[0]);
      List *fmt_val = argv[1];
      ASSERT_EVAL(fmt_val->nonempty());
      string_ref fmt = fmt_val->symbol;
      //      i32 i = 0;
      //      i32 arg_id = 0;

      //      while (i < fmt.len) {
      //        char c = fmt.ptr[c];
      //        if (c == "%") {
      //          ASSERT_EVAL(arg_id < argc - 2);
      //          EVAL_LLVM(arg, argv[2 + arg_id]);
      //          if (arg->getType() == llvm::Type::getInt32Ty(c)) {
      //            llvm_builder->CreateCall(module->getFunction("fmt_insert_"), argv_values);
      //          }
      //        }
      //      }

      llvm::SmallVector<llvm::Value *, 4> argv_values;
      argv_values.push_back(buf);
      argv_values.push_back(lookup_string(fmt));
      ito(argc - 2) {
        EVAL_LLVM(val, argv[2 + i]);
        if (val->getType() == llvm::Type::getFloatTy(c)) {
          // conversion due to C lib standard
          val = llvm_builder->CreateFPExt(val, llvm::Type::getDoubleTy(c));
        }
        argv_values.push_back(val);
      }
      return wrap_value(llvm_builder->CreateCall(module->getFunction("ll_format"), argv_values));
    }
    else if (l->cmp_symbol("puts")) {
      ASSERT_EVAL(argc == 1);
      EVAL_LLVM(val, argv[0]);
      llvm_builder->CreateCall(module->getFunction("ll_puts"), {val});
      return NULL;
    }
    else if (l->cmp_symbol("putnl")) {
      ASSERT_EVAL(argc == 0);
      llvm_builder->CreateCall(module->getFunction("ll_puts"), {lookup_string(stref_s("\n"))});
      return NULL;
    }
    else if (l->cmp_symbol("assert")) {
      ASSERT_EVAL(argc == 1);
      EVAL_LLVM(val, argv[0]);
      llvm::Value *str = lookup_string(argv[0]->get_umbrella_string());
      llvm_builder->CreateCall(ll_assert, {val, str});
      return NULL;
    }
    else if (l->cmp_symbol("debug_assert")) {
      ASSERT_EVAL(argc == 1);
      EVAL_LLVM(val, argv[0]);
      llvm::Value *str = lookup_string(argv[0]->get_umbrella_string());
      llvm_builder->CreateCall(ll_debug_assert, {val, str});
      return NULL;
    }
    else if (l->cmp_symbol("assume")) {
      ASSERT_EVAL(argc == 1);
      EVAL_LLVM(val, argv[0]);
      //      if (val->getType() == llvm::Type::getInt1Ty(c)) {
      //        val = llvm_builder->CreateSExt(val, llvm::Type::getInt8Ty(c));
      //      }
      llvm_builder->CreateIntrinsic(llvm::Intrinsic::assume, {}, {val});
      return NULL;
    }
    else if (l->cmp_symbol("jmp")) {
      ASSERT_EVAL(argc == 1);
      Deferred_Branch db = {};
      db.true_target     = argv[0]->get_symbol();
      db.src             = cur_bb;
      deferred_branches.push(db);
      return NULL;
    }
    else if (l->cmp_symbol("br")) {
      ASSERT_EVAL(argc == 3);
      Deferred_Branch db = {};
      db.cond            = llvm_eval(l->next);
      db.true_target     = l->get(2)->get_symbol();
      db.false_target    = l->get(3)->get_symbol();
      db.src             = cur_bb;
      deferred_branches.push(db);
      return NULL;
    }
    else if (l->cmp_symbol("module")) {
      auto mbuf = llvm::MemoryBuffer::getMemBuffer(
          llvm::StringRef((char *)ll_stdlib_bc, ll_stdlib_bc_len), "", false);
      ASSERT_ALWAYS(module == NULL && "No nested modules");
      llvm::SMDiagnostic error;
      module = llvm::parseIR(*mbuf.get(), error, c);
      ASSERT_ALWAYS(module);
      LOOKUP_FN(ll_printf);
      LOOKUP_FN(ll_assert);
      LOOKUP_FN(ll_debug_assert);
      state->symbol_table.enter_scope();
      defer(state->symbol_table.exit_scope());
      List *cur = l->next;
      while (cur != NULL) {
        CHK_ERR(global_eval(cur));
        cur = cur->next;
      }
      llvm::StripDebugInfo(*module);
      std::string              str;
      llvm::raw_string_ostream os(str);
      {
        str.clear();
        module->print(os, NULL);
        os.flush();
        dump_file("module.ll", str.c_str(), str.size());
      }
      {
        std::unique_ptr<llvm::legacy::PassManager> FPM =
            std::make_unique<llvm::legacy::PassManager>();
        FPM->add(llvm::createFunctionInliningPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createReassociatePass());
        FPM->add(llvm::createGVNPass());
        FPM->add(llvm::createCFGSimplificationPass());
        FPM->add(llvm::createGlobalDCEPass());
        FPM->add(llvm::createSROAPass());
        FPM->add(llvm::createEarlyCSEPass());
        FPM->add(llvm::createReassociatePass());
        FPM->add(llvm::createConstantPropagationPass());
        FPM->add(llvm::createDeadInstEliminationPass());
        FPM->add(llvm::createFunctionInliningPass());
        FPM->add(llvm::createCFGSimplificationPass());
        FPM->add(llvm::createPromoteMemoryToRegisterPass());
        FPM->add(llvm::createAggressiveDCEPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createDeadInstEliminationPass());
        FPM->add(llvm::createSROAPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createCFGSimplificationPass());
        FPM->add(llvm::createPromoteMemoryToRegisterPass());
        FPM->add(llvm::createReassociatePass());
        FPM->add(llvm::createIPConstantPropagationPass());
        FPM->add(llvm::createDeadArgEliminationPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createCFGSimplificationPass());
        FPM->add(llvm::createPruneEHPass());
        FPM->add(llvm::createReversePostOrderFunctionAttrsPass());
        FPM->add(llvm::createConstantPropagationPass());
        FPM->add(llvm::createDeadInstEliminationPass());
        FPM->add(llvm::createCFGSimplificationPass());
        FPM->add(llvm::createArgumentPromotionPass());
        FPM->add(llvm::createAggressiveDCEPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createJumpThreadingPass());
        FPM->add(llvm::createCFGSimplificationPass());
        FPM->add(llvm::createSROAPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createTailCallEliminationPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createEarlyCSEPass());
        FPM->add(llvm::createFunctionInliningPass());
        FPM->add(llvm::createConstantPropagationPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createIPSCCPPass());
        FPM->add(llvm::createDeadArgEliminationPass());
        FPM->add(llvm::createAggressiveDCEPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createCFGSimplificationPass());
        FPM->add(llvm::createFunctionInliningPass());
        FPM->add(llvm::createArgumentPromotionPass());
        FPM->add(llvm::createSROAPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createCFGSimplificationPass());
        FPM->add(llvm::createReassociatePass());
        FPM->add(llvm::createLoopRotatePass());
        FPM->add(llvm::createLICMPass());
        FPM->add(llvm::createLoopUnswitchPass(false));
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createIndVarSimplifyPass());
        FPM->add(llvm::createLoopIdiomPass());
        FPM->add(llvm::createLoopDeletionPass());
        FPM->add(llvm::createLoopUnrollPass());
        FPM->add(llvm::createGVNPass());
        FPM->add(llvm::createMemCpyOptPass());
        FPM->add(llvm::createSCCPPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createJumpThreadingPass());
        FPM->add(llvm::createCorrelatedValuePropagationPass());
        FPM->add(llvm::createDeadStoreEliminationPass());
        FPM->add(llvm::createAggressiveDCEPass());
        FPM->add(llvm::createCFGSimplificationPass());
        FPM->add(llvm::createInstructionCombiningPass());
        FPM->add(llvm::createAggressiveInstCombinerPass());
        FPM->add(llvm::createFunctionInliningPass());
        FPM->add(llvm::createAggressiveDCEPass());
        FPM->add(llvm::createStripDeadPrototypesPass());
        FPM->add(llvm::createGlobalDCEPass());
        FPM->add(llvm::createGlobalOptimizerPass());
        FPM->add(llvm::createConstantMergePass());
        FPM->run(*module);
      }
      {
        str.clear();
        module->print(os, NULL);
        os.flush();
        dump_file("module.opt.ll", str.c_str(), str.size());
      }
      std::unique_ptr<llvm::orc::LLJIT> jit;
      llvm::ExitOnError                 ExitOnErr;
      llvm::InitializeNativeTarget();
      llvm::InitializeNativeTargetAsmPrinter();
      jit = ExitOnErr(llvm::orc::LLJITBuilder().create());
      ExitOnErr(
          jit->addIRModule(llvm::orc::ThreadSafeModule(std::move(module), std::move(context))));
      static_cast<llvm::orc::RTDyldObjectLinkingLayer &>(jit->getObjLinkingLayer())
          .registerJITEventListener(*llvm::JITEventListener::createGDBRegistrationListener());
      jit->getIRTransformLayer().setTransform(
          [&](llvm::orc::ThreadSafeModule TSM, const llvm::orc::MaterializationResponsibility &R) {
            TSM.withModuleDo([&](llvm::Module &M) {

            });
            return TSM;
          });
      jit->getMainJITDylib().addGenerator(
          ExitOnErr(llvm::orc::DynamicLibrarySearchGenerator::GetForCurrentProcess(
              jit->getDataLayout().getGlobalPrefix())));

      auto entry = (int (*)(int, char **))ExitOnErr(jit->lookup("main")).getAddress();
      if (entry != NULL) {
        entry(0, 0);
      } else {
        ASSERT_EVAL(false && "Couldn't find an entry point");
      }
      return NULL;
    }
    else if (l->cmp_symbol("function")) {
      state->symbol_table.enter_scope();
      defer(state->symbol_table.exit_scope());
      ASSERT_EVAL(cur_fun == NULL);
      List * func_node   = l;
      List * return_type = func_node->get(1);
      Value *name        = CALL_EVAL(func_node->get(2));
      ASSERT_SMB(name);
      List *args = func_node->get(3);
      TMP_STORAGE_SCOPE;
      {
        llvm::SmallVector<llvm::Type *, 4> argv;
        llvm::SmallVector<std::string, 4>  argv_names;
        ASSERT_EVAL(args->child != NULL);
        List *arg = args->child;
        while (arg != NULL) {
          NOTNULL(arg->child);
          List *arg_type = arg->child->get(0);
          List *arg_name = arg->child->get(1);
          argv.push_back(parse_type(arg_type));
          argv_names.push_back(stref_to_tmp_cstr(arg_name->symbol));
          arg = arg->next;
        }
        cur_fun = llvm::Function::Create(
            llvm::FunctionType::get(parse_type(return_type), argv, false),
            llvm::Function::LinkageTypes::ExternalLinkage,
            llvm::Twine(llvm::StringRef(name->str.ptr, name->str.len)), *module);
        alloca_bb = llvm::BasicBlock::Create(c, "allocas", cur_fun);
        cur_bb    = alloca_bb;
        llvm_builder.reset(new LLVM_IR_Builder_t(alloca_bb, llvm::NoFolder()));
        ito(argv.size()) {
          state->symbol_table.add_symbol(move_cstr(stref_s(argv_names[i].c_str())),
                                         wrap_value(cur_fun->getArg(i)));
        }
        if (target_avx2) cur_fun->addFnAttr("target-features", "+avx2");
      }
      state->symbol_table.enter_scope();
      defer(state->symbol_table.exit_scope());
      List *cur = func_node->get(4);
      while (cur != NULL) {
        CHK_ERR(global_eval(cur));
        cur = cur->next;
      }
      ito(deferred_branches.size) {
        Deferred_Branch &db = deferred_branches[i];
        if (db.cond != NULL) { // cond branch
          ASSERT_EVAL(labels.contains(db.true_target));
          ASSERT_EVAL(labels.contains(db.false_target));
          llvm::BasicBlock *true_target  = labels.get(db.true_target);
          llvm::BasicBlock *false_target = labels.get(db.false_target);
          llvm::BranchInst::Create(true_target, false_target, db.cond, db.src);
        } else {
          ASSERT_EVAL(labels.contains(db.true_target));
          llvm::BasicBlock *true_target = labels.get(db.true_target);
          llvm::BranchInst::Create(true_target, db.src);
        }
      }
      deferred_branches.release();
      deferred_branches.init();
      labels.release();
      labels.init();
      cur_fun = NULL;
      return NULL;
    }
    else if (l->cmp_symbol("label")) {
      List *            label_name = l->get(1);
      llvm::BasicBlock *new_bb =
          llvm::BasicBlock::Create(c, stref_to_tmp_cstr(label_name->symbol), cur_fun);
      labels.insert(label_name->symbol, new_bb);
      if (cur_bb == alloca_bb) {
        llvm::BranchInst::Create(new_bb, cur_bb);
      }
      cur_bb = new_bb;
      llvm_builder.reset(new LLVM_IR_Builder_t(cur_bb, llvm::NoFolder()));
      return NULL;
    }
    else if (l->cmp_symbol("call")) {
      List *                              name = l->get(1);
      llvm::SmallVector<llvm::Value *, 4> argv_values;
      ito(argc - 1) {
        EVAL_LLVM(val, argv[1 + i]);
        argv_values.push_back(val);
      }

      return wrap_value(llvm_builder->CreateCall(
          module->getFunction(llvm::StringRef(name->symbol.ptr, name->symbol.len)), argv_values));
    }
    else if (l->cmp_symbol("ret")) {
      if (argc > 0) {
        ASSERT_EVAL(argc == 1);
        EVAL_LLVM(val, argv[0]);
        llvm::ReturnInst::Create(c, val, cur_bb);
      } else {
        llvm::ReturnInst::Create(c, NULL, cur_bb);
      }
      cur_bb = NULL;
      llvm_builder.release();
      return NULL;
    }
    else if (l->cmp_symbol("typeof")) {
      EVAL_LLVM(val, argv[0]);
      return wrap_type(val->getType());
    }
    else if (l->cmp_symbol("ignore")) {
      return NULL;
    }
    //    else {
    //      Value *raw_val = state->symbol_table.lookup_value(l->symbol);
    //      if (raw_val != NULL && raw_val->type == (i32)Value::Value_t::ANY &&
    //          raw_val->any_type == (i32)LLVM_Value_t::VALUE) {
    //        llvm::Value *val = (llvm::Value *)raw_val->any;
    //        ASSERT_EVAL(val);
    //        return wrap_value(val);
    //      }
    //    }
    else { // no match
      if (prev != NULL) {
        return prev->eval(l);
      }
      return {NULL, false};
    }
    TRAP;
  }

  llvm::Value *llvm_eval(List *l) {
    Match match = global_eval(l);
    if (match.match && match.val != NULL) {
      if (match.val->type == (i32)Value::Value_t::ANY &&
          match.val->any_type == (i32)LLVM_Value_t::VALUE) {
        llvm::Value *val = (llvm::Value *)match.val->any;
        ASSERT_EVAL(val);
        return val;
      } else if (match.val->type == (i32)Value::Value_t::I32) {
        return llvm_get_constant_i32(match.val->i);
      } else if (match.val->type == (i32)Value::Value_t::F32) {
        return llvm_get_constant_f32(match.val->f);
      } else if (match.val->type == (i32)Value::Value_t::SYMBOL) {
        return lookup_string(match.val->str);
      }
    } else {
      ASSERT_EVAL(false && "Failed to evaluate LLVM value");
    }
    TRAP;
  }
};
#endif

IEvaluator *g_head = NULL;

IEvaluator *IEvaluator::get_head() {
  if (g_head == NULL) {
    Default_Evaluator *head = new Default_Evaluator();
    head->init();
    g_head = head;
  }
  return g_head;
}

void IEvaluator::set_head(IEvaluator *newhead) { g_head = newhead; }

IEvaluator *IEvaluator::create_mode(string_ref name) {
  static LLVM_Evaluator *eval = NULL;
  if (name == stref_s("llvm")) {
    if (eval == NULL) {
      eval        = new LLVM_Evaluator();
      eval->state = get_head()->state;
      eval->prev  = get_head();
      eval->init();
    }
    return eval;
  }
  return NULL;
}
void global_set_evaluation_error() { IEvaluator::get_head()->set_error(); }
void parse_and_eval(string_ref text) {
  Evaluator_State state;
  state.init();
  defer(state.release());

  struct List_Allocator {
    Evaluator_State *state;
    List *           alloc() {
      List *out = state->list_storage.alloc_zero(1);
      return out;
    }
  } list_allocator;
  list_allocator.state = &state;
  List *root           = List::parse(text, list_allocator);
  if (root == NULL) {
    state.push_error("Couldn't parse");
    return;
  }
  root->dump_list_graph();

  IEvaluator::get_head()->state = &state;
  IEvaluator::get_head()->eval(root);
}

int main(int argc, char **argv) {
  TMP_STORAGE_SCOPE;

  parse_and_eval(stref_s(read_file_tmp(argv[1])));

  return 0;
}
#endif
