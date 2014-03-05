#include <memory>
#include <list>
#include <boost/format.hpp>
#include <boost/utility.hpp>
#include <boost/atomic.hpp>
#include <boost/thread.hpp>
#include <boost/smart_ptr.hpp>
#include <boost/timer/timer.hpp>
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <stdint.h>
#include <fcntl.h>

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#include <io.h>
typedef int ssize_t;
#else
#include <unistd.h>
#define O_BINARY 0
#endif

/** Buffer for a single chunk of data
 */
class buffer : boost::noncopyable
{
  boost::scoped_array<uint8_t> m_data;
  boost::atomic<int> m_refcount;
  size_t m_maxsize;
  size_t m_size;

public:
  typedef boost::shared_ptr<buffer> ptr;

  buffer(int maxsize)
    : m_data(new uint8_t[maxsize]),
      m_refcount(0),
      m_maxsize(maxsize),
      m_size(0)
  { }

  void acquire(int count = 1) {
    // memory order can be relaxed since synchronization
    // will be used for cross-thread comunication anyway
    m_refcount.fetch_add(count, boost::memory_order_relaxed);
  }

  bool release(int count = 1) {
    if (m_refcount.fetch_sub(count, boost::memory_order_release) <= count) {
      boost::atomic_thread_fence(boost::memory_order_acquire);
      return true;
    }
    return false;
  }

  uint8_t* get() const {
    return m_data.get();
  }

  size_t maxsize() const {
    return m_maxsize;
  }

  void size(size_t newsize) {
    m_size = std::min(newsize, m_maxsize);
  }

  size_t size() const {
    return m_size;
  }
};

/** Thread-safe queue
 */
template<class T>
class safe_queue
{
  bool m_done;
  std::list<T> m_queue;
  boost::mutex m_mutex;
  boost::condition_variable m_not_empty;

public:
  typedef boost::shared_ptr<safe_queue> ptr;

  safe_queue()
    : m_done(false)
  { }

  void push(const T& value) {
    boost::unique_lock<boost::mutex> lock(m_mutex);
    bool was_empty = m_queue.empty();
    m_queue.push_back(value);
    if (was_empty) {
      m_not_empty.notify_one();
    }
  }

  bool pop(T& value) {
    boost::unique_lock<boost::mutex> lock(m_mutex);
    while (m_queue.empty()) {
      if (m_done) {
        return false;
      }
      m_not_empty.wait(lock);
    }
    value = m_queue.front();
    m_queue.pop_front();
    return true;
  }

  void done() {
    boost::unique_lock<boost::mutex> lock(m_mutex);
    m_done = true;
    m_not_empty.notify_all();
  }
};

/** Base class for threads that calculate hashes
 */
class hash_thread_base
{
  std::string m_name;
  safe_queue<buffer::ptr> m_input;
  safe_queue<buffer::ptr>::ptr m_freequeue;

protected:
  hash_thread_base(const std::string& name, safe_queue<buffer::ptr>::ptr freequeue)
    : m_name(name), m_freequeue(freequeue)
  {
  }

  bool pop(buffer::ptr& chunk) {
    return m_input.pop(chunk);
  }

  void release(buffer::ptr chunk) {
    if (chunk->release()) {
      m_freequeue->push(chunk);
    }
  }

public:
  typedef boost::shared_ptr<hash_thread_base> ptr;

  std::string name() const {
    return m_name;
  }

  void push(buffer::ptr chunk) {
    m_input.push(chunk);
  }

  void done() {
    m_input.done();
  }

  virtual void start() = 0;
  virtual void join() = 0;
  virtual std::string hexdigest() = 0;
};

/** Implementation of hash_thread for a particular algorithm
 */
template<class HashAlgorithm>
class hash_thread : public hash_thread_base
{
  HashAlgorithm m_hash;
  boost::thread m_thread;

  void worker() {
    buffer::ptr chunk;
    while (pop(chunk)) {
      m_hash.Update(chunk->get(), chunk->size());
      release(chunk);
    }
  }

public:
  hash_thread(const std::string& name, safe_queue<buffer::ptr>::ptr freequeue)
    : hash_thread_base(name, freequeue)
  { }

  virtual void start() override {
    boost::thread thread(&hash_thread::worker, this);
    m_thread.swap(thread);
  }

  virtual void join() override {
    m_thread.join();
  }

  virtual std::string hexdigest() override {
    boost::scoped_array<uint8_t> digest(new uint8_t[m_hash.DigestSize()]);
    m_hash.Final(digest.get());
    std::string hexdigest(m_hash.DigestSize() * 2, 0);
    for (size_t i = 0, j = 0; i < m_hash.DigestSize(); ++i) {
      uint8_t k = digest[i];
      hexdigest[j++] = "0123456789abcdef"[k >> 4];
      hexdigest[j++] = "0123456789abcdef"[k & 15];
    }
    return hexdigest;
  }
};

/** Low-level file IO with less overhead
 */
class iofile : boost::noncopyable
{
private:
  int m_fd;

public:
  bool operator!() const {
    return m_fd == -1;
  }

  iofile()
    : m_fd(-1)
  { }

  iofile(const char* filename, int flags)
    : m_fd(-1)
  {
    open(filename, flags);
  }

  ~iofile() {
    close();
  }

  bool open(const char* filename, int flags) {
    if (m_fd != -1) {
      ::close(m_fd);
      m_fd = -1;
    }
    m_fd = ::open(filename, flags);
    return m_fd != -1;
  }

  void close() {
    if (m_fd != -1) {
      ::close(m_fd);
      m_fd = -1;
    }
  }

  ssize_t read(void* buf, size_t count) {
    return ::read(m_fd, buf, count);
  }

  ssize_t write(const void* buf, size_t count) {
    return ::write(m_fd, buf, count);
  }
};

int main(int argc, char** argv)
{
  bool errors = false;
  const size_t chunk_size = 65536;
  const size_t readahead_size = 1048576;

  for (int i = 1; i < argc; ++i) {
    const char* filename = argv[i];
    std::cout << filename << "...";

    iofile fd(filename, O_RDONLY | O_BINARY);
    if (!fd) {
      std::cout << " error opening file!" << std::endl;
      errors = true;
      continue;
    }

    safe_queue<buffer::ptr>::ptr buffers = boost::make_shared< safe_queue<buffer::ptr> >();
    for (size_t i = 0; i < readahead_size / chunk_size; ++i) {
      buffers->push(boost::make_shared<buffer>(chunk_size));
    }

    std::vector<hash_thread_base::ptr> hash_threads;
    hash_threads.push_back(boost::make_shared< hash_thread<CryptoPP::MD5> >("md5", buffers));
    hash_threads.push_back(boost::make_shared< hash_thread<CryptoPP::SHA1> >("sha1", buffers));
    hash_threads.push_back(boost::make_shared< hash_thread<CryptoPP::SHA256> >("sha256", buffers));
    hash_threads.push_back(boost::make_shared< hash_thread<CryptoPP::SHA512> >("sha512", buffers));
    for (const auto& hthread : hash_threads) {
      hthread->start();
    }

    bool ok = true;
    buffer::ptr chunk;
    uint64_t filesize = 0;
    boost::timer::cpu_timer timer;
    while (buffers->pop(chunk)) {
      ssize_t nbytes = fd.read(chunk->get(), chunk->maxsize());
      if (nbytes == 0)
        break;
      if (nbytes < 0) {
        std::cout << " error reading file!" << std::endl;
        errors = true;
        ok = false;
        break;
      }
      chunk->size(nbytes);
      chunk->acquire(hash_threads.size());
      for (const auto& hthread : hash_threads) {
        hthread->push(chunk);
      }
      filesize += nbytes;
    }

    for (const auto& hthread : hash_threads) {
      hthread->done();
      hthread->join();
    }

    if (!ok) {
      continue;
    }

    boost::timer::cpu_times times = timer.elapsed();

    std::cout << boost::format(" %d bytes (%.2fMB/s)") % filesize % ((double)filesize / 1048576.0 / (times.wall / 1000000000.0)) << std::endl;
    for (const auto& hthread : hash_threads) {
      std::cout << "\t" << hthread->name() << "\t" << hthread->hexdigest() << std::endl;
    }
  }

  if (errors) {
    return 1;
  }

  return 0;
}
