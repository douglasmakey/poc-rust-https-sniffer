# Uprobes siblings - Capturing HTTPS Traffic. A Rust and eBPF Odyssey

In one of my previous article, ["The Beginning of My eBPF Journey: Kprobe & BCC"](https://www.kungfudev.com/blog/2023/10/14/the-beginning-of-my-ebpf-journey-kprobe-bcc), we delved into the intricacies of kernel probes (`kprobes`). As we continue our journey into the depths of eBPF, this article shifts focus to another powerful aspect of eBPF instrumentation: *User Space Probes*, commonly known as `uprobes`.

`Uprobes` provide a window into the *user space*, allowing us to hook into function calls and instructions within user space applications. This capability opens up a surplus of opportunities for performance analysis, debugging, and gaining insights into application behavior in a real environment.

In this article, we'll build a basic version of an HTTPS sniffer, inspired by [bcc-sslsniff.py](https://github.com/iovisor/bcc/blob/master/tools/sslsniff.py), but we'll use Rust and Aya. We're going to demonstrate the capabilities of `uprobes` by employing `uprobe` and `uretprobe` along with familiar maps like `PerCpuArray`, `HashMap`, and `PerEventArray`. This will be a straightforward example to help us explore how `uprobes` function.

In our application, we'll focus exclusively on targeting `OpenSSL` to capture raw communications. Utilizing the `uprobes` and other tools we've discussed, our aim is to gather all the relevant data transmitted through OpenSSL and display it. This approach keeps our implementation simple and direct, allowing us to concentrate on the core functionality of capturing and printing the raw communication data.

## **Why Uprobes?**

While `kprobes` give us visibility into kernel operations, they don't offer direct insight into what's happening in user space applications. The `uprobes` fill this gap. They are particularly useful in scenarios where understanding the interaction between user space applications and the operating system is crucial. Some `uprobes` possibilities:

1. **Potential in Application Performance**: Uprobes could be used to analyze and potentially enhance the efficiency of functions within applications by timing their execution and identifying slow areas.
2. **Possibility for Debugging**: They could offer a less intrusive alternative for collecting data in production environments, which might help in diagnosing complex issues.
3. **Opportunity for Enhanced Observability**: In observability and monitoring, `uprobes` could provide crucial data points, potentially enriching our understanding of how applications behave in real-world scenarios.

```txt
 +----------------------+     +-------------+     +-----------------+     +--------------------+
 | User Space Application|     | Linux Kernel|     |   eBPF Program  |     |   uprobe function  |
 +----------------------+     +-------------+     +-----------------+     +--------------------+
        |                         |                     |                          |
        |                         |                     |                          |
        | Attach uprobe           |                     |                          |
        |------------------------>|                     |                          |
        |                         |                     |                          |
        |                         | Load eBPF Program   |                          |
        |                         |------------------->|                           |
        |                         |                     |                          |
        |                         |                     | Attach to user function  |
        |                         |                     |------------------------->|
        |                         |                     |                          |
        |                         |                     |                          |
        | User function called    |                     |                          |
        |------------------------>|                     |                          |
        |                         |                     |                          |
        |                         |                     | Execute eBPF actions     |
        |                         |                     |------------------------->|


```
  
Under the hood, `uprobes` work by instrumenting user space binaries at specific points, usually function entry or exit points. Here's an ultra simplified explanation:

1. **Instrumentation Point Identification**: You identify a specific location within the user space binary (e.g., the entry or exit point of a function).
2. **Kernel Registration**: Both `uprobe` (at the entry) and `uretprobe` (at the exit) are registered with the kernel.
3. **Execution Intercept**: When the program hits these points, the kernel triggers the respective probes.
4. **eBPF Program Execution**: Each probe is linked to an eBPF program. The `uprobe` eBPF program executes at function entry, and the `uretprobe` eBPF program runs at function exit. These programs can gather data or manipulate the process state.
5. **Process Continuation**: After the eBPF programs execute, control returns to the original process, allowing it to continue normally.

## Exploring PerfEventArray in Rust

In the initial article of this series, we briefly touched upon `BPF_PERF_OUTPUT`, a BPF map type for efficiently sending event data to **user space** via a perf ring buffer. While we didn't delve deeply into it then, we're now taking a closer look, especially as we're working with Rust, where it's known as `PerfEventArray`. The `PerfEventArray` (`BPF_MAP_TYPE_PERF_EVENT_ARRAY` in eBPF) utilizes a ring buffer within `mmap()`ed shared memory, optimizing data transfer from kernel to user space. Accessible through memory mapping, this setup allows quick and direct access to data from the kernel. Each CPU's entry in this array facilitates fast, simultaneous data transmission across multiple CPUs. Particularly effective for handling large data volumes, such as network packets or system call data, `PerfEventArray` in Rust becomes a crucial tool for high-throughput and low-overhead data processing in eBPF applications.

## Exploring OpenSSL: A Key Player in TLS/SSL Protocols

In the world of TLS/SSL, the heavy lifting occurs in the `user-space`, not in the kernel. This is where libraries like **OpenSSL** come into play. These libraries are responsible for managing the intricate details of the TLS/SSL protocols, including the crucial handshake process that establishes a secure connection. Beyond just establishing secure channels, they provide a suite of functions essential for encrypting and decrypting data transmitted over these connections. By handling the complexities of the handshake and offering encryption/decryption capabilities, libraries like OpenSSL play a pivotal role in securing internet communications.

We'll focus on the interaction between an application and the OpenSSL library. Our sniffer will hook into the `SSL_write` and `SSL_read` functions of the OpenSSL library, which are responsible for encrypting and decrypting data sent over a network. By attaching `uprobes` to these functions, we'll be able to observe the data before it's encrypted and after it's decrypted. This process will help us understand how secure communications function and how tools like `uprobes` can be used to monitor this data as it moves through an application to the system.


```text
								+-----------------------------+
								|         Application         |
								+----write----------- read----+
									   |                |
								+-----------------------------+
								|      TLS Library            |
								|  (e.g. openssl.so)          |
								+-----------------------------+
								| SSL_write   |   SSL_read    |
								+-------------+---------------+
								       |                |
								+------+----------------+-----+
								|        Linux Kernel         |
								+-----------------------------+
								|      send   |   recv        |
								+---------+------+------+-----+

```

Programs like `curl`, which need TLS for secure protocols, often use **OpenSSL**. You can check this by running `curl -V` to see the info about the SSL/TLS library.

```bash
curl -V
curl 7.81.0 (x86_64-pc-linux-gnu) libcurl/7.81.0 OpenSSL/3.0.2 zlib/1.2.11 
Release-Date: 2022-01-05
Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt 
...
```

So in my machine when I use the `curl` command for HTTPS websites, it's the `OpenSSL` library that handles the secure TLS communications. To confirm and get more details, we can use the `ldd` command. This command shows us the shared libraries used by `curl`. Among them, you'll find `libssl`, which is part of `OpenSSL`, proving that `curl` uses it for SSL/TLS. The `ldd` output also shows where the `libssl` library is located, which is crucial information because we'll need this path to attach our `uprobes` to the `libssl` library to monitor the data handling.

```bash
$ ldd `which curl` | grep -E 'ssl'
libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x00007f46928ef000)
```

We've determined that `SSL_read` and `SSL_write` are crucial functions in **OpenSSL** for encryption and decryption. Our plan is to attach `uprobes` to these functions. To ensure these functions are indeed part of the OpenSSL library and to potentially obtain their address pointers if needed, we'll inspect the library's symbol table. Tools such as `nm`, `llvm-objdump`, or `objdump` are perfect for this, allowing us to verify the presence of `SSL_read` and `SSL_write` in the symbol table of the specific file we're examining.

> A symbol table is a data structure used in computer programming, particularly in the compilation and linking process, to store information about the identifiers (like variable and function names) used in a program. It maps each identifier to information such as its location, type, scope, and address. In the context of shared libraries like OpenSSL's `libssl.so`, a symbol table helps in locating the addresses of specific functions (like `SSL_read` and `SSL_write`). This is crucial for tasks like debugging or attaching probes in performance monitoring, as it allows precise identification and interaction with specific parts of the binary.

```bash
nm -D /lib/x86_64-linux-gnu/libssl.so.3 | grep SSL_read
0000000000032c90 T SSL_read@@OPENSSL_3.0.0
0000000000038ca0 T SSL_read_early_data@@OPENSSL_3.0.0
0000000000032d10 T SSL_read_ex@@OPENSSL_3.0.0
```

We focus on attaching uprobes inside the OpenSSL library because tools like `curl` use dynamic linking to access OpenSSL's functionalities. Dynamic linking means these applications connect to the OpenSSL library at runtime, not at the time they're compiled. This approach is common for flexibility and efficiency. By attaching our `uprobes` to OpenSSL, we effectively monitor all applications that dynamically link to it, capturing a wide range of data from any program using **OpenSSL for SSL/TLS** operations. This makes our sniffer versatile, capable of monitoring various applications without needing specific probes for each one.

> In contrast, for applications that statically link OpenSSL, the library's code is embedded directly into the application itself. This creates a different scenario for uprobes. Each of these applications contains its own version of OpenSSL, distinct from others. Additionally, if they're compiled with performance optimization flags, this can alter the symbol table by modifying or removing function entries. As a result, attaching uprobes to the central OpenSSL library doesn't affect these applications. Monitoring them would require a more tailored approach, attaching uprobes to each individual executable that has OpenSSL statically linked.

Now that we've covered the necessary background, we have a clear understanding to begin our experiment.

## Diving Into the Code: Crafting Our HTTPS Sniffer

In my last article, I briefly explained starting a project with rust-aya, including using their scaffolding generator. If you need a refresher, feel free to revisit that [article](https://www.kungfudev.com/blog/2023/11/21/ddos-mitigation-with-rust-and-aya) or check the [rust-aya](https://aya-rs.dev/book/) documentation.

### Kernel-Space Component

Let's begin with the `kernel-space` component located in `/https-sniffer-ebpf/src/main.rs`. I'll break down the code and highlight the key parts for better understanding. First, we'll declare our uprobes (uprobe and uretprobe) for each function.

```rust
#[uprobe]
pub fn ssl_read(ctx: ProbeContext) -> u32 {
    match try_ssl(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn ssl_read_ret(ctx: ProbeContext) -> u32 {
    match try_ssl_ret(ctx, Kind::Read) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    match try_ssl(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[uretprobe]
pub fn ssl_write_ret(ctx: ProbeContext) -> u32 {
    match try_ssl_ret(ctx, Kind::Write) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

```

In this snippet, we're seeing a familiar pattern from our last article, here we implement `uprobes` and `uretprobes` using Rust macros. Each function is marked with either `#[uprobe]` or `#[uretprobe]` to designate its role. The `ssl_read` and `ssl_write` functions, marked with `#[uprobe]`, are our entry points for capturing data when the SSL read and write operations begin. The corresponding `ssl_read_ret` and `ssl_write_ret` functions, marked with `#[uretprobe]`, are triggered when these operations complete. We're reusing the `try_ssl` and `try_ssl_ret` functions for both SSL read and write operations because of their similarity. This approach is suitable for our simple program that focuses on capturing the data being encrypted and decrypted. By doing so, we maintain simplicity in our code while effectively monitoring the SSL data flow.

In our project, we will use various maps for data management:

```rust
#[map]
static mut STORAGE: PerCpuArray<Data> = PerCpuArray::with_max_entries(1, 0);
#[map]
static mut EVENTS: PerfEventArray<Data> = PerfEventArray::with_max_entries(1024, 0);
#[map]
static mut BUFFERS: HashMap<u32, *const u8> = HashMap::with_max_entries(1024, 0);

```

`STORAGE` is a `PerCpuArray` for storing data on a per-CPU basis, preventing interference between CPUs. `EVENTS`, a `PerfEventArray`, facilitates data transfer from the kernel to user space. `BUFFERS` is a `HashMap` that links each thread or process to a buffer pointer, essential for handling data in SSL functions. It stores buffer pointers when SSL functions are invoked and retrieves them for specific threads or processes, ensuring efficient data tracking and manipulation.

Let's delve into the `try_ssl` function, which is relatively simple in operation. Its main task is to capture the thread group ID **(tgid)** and the buffer pointer from an SSL read or write function. This buffer pointer is then stored in the `BUFFERS` map for future handling.

```rust
// `try_ssl` function is an eBPF probe for capturing SSL data.
fn try_ssl(ctx: ProbeContext) -> Result<u32, u32> {
    let tgid: u32 = bpf_get_current_pid_tgid() as u32;
    // Get the buffer pointer (second argument of the probed function) from the context.
    let buf_p: *const u8 = ctx.arg(1).ok_or(0_u32)?;
    // Insert the buffer pointer into the `BUFFERS` map for the current process/thread group.
    unsafe { BUFFERS.insert(&tgid, &buf_p, 0).map_err(|e| e as u8)? };
    Ok(0)
}
```

> Using `*const u8` (a pointer to an unsigned 8-bit integer, or byte) is a common and safe way to represent raw memory addresses in Rust. It allows us to access the data pointed to by the buffer pointer in a byte-wise manner, which is typical in low-level data manipulation.

We obtain the buffer pointer from `ctx` at argument position 1. This mirrors the original SSL function prototypes, where `buf` is the second argument, corresponding to position 1 in the context:

```c
int SSL_read(SSL *ssl, void *buf, int num);
int SSL_write(SSL *ssl, const void *buf, int num);
```

This approach ensures we accurately track the data buffer being read from or written to during SSL operations.

Now that we've set up the entry point `uprobes` for `SSL_read` and `SSL_write`, our next step is to probe their exit points. With the `try_ssl_ret` function. 

```rust
// `try_ssl_ret` function is an eBPF probe for handling the return value of an SSL function.
fn try_ssl_ret(ctx: ProbeContext, kind: Kind) -> Result<u32, u32> {
    // `retval` represents the number of bytes actually read from the TLS/SSL connection.
    // This value is crucial as it indicates the success of the read operation and the size of the data read.
    let retval: i32 = ctx.ret().ok_or(0u32)?;
    if retval <= 0 {
        return Ok(0);
    }
    ...
}
```

We begin by capturing the return value of these functions, which indicates the number of bytes actually read or written in the TLS/SSL connection. We retrieve the `retval` from the context. A non-positive `retval` indicates an unsuccessful operation, in which case we end the probe. Otherwise, we proceed, using this value to determine the amount of data handled in the operation.

In this part of the `try_ssl_ret` function, we manage data buffers while addressing eBPF programming constraints.

```rust
let tgid: u32 = bpf_get_current_pid_tgid() as u32;
// Retrieve the buffer pointer from the `BUFFERS` map for the current process/thread group.
let buf_p = unsafe {
	let ptr = BUFFERS.get(&tgid).ok_or(0_u32)?;
	*ptr
};

if buf_p.is_null() {
	return Ok(0);
}

let data = unsafe {
	let ptr = STORAGE.get_ptr_mut(0).ok_or(0_u32)?;
	&mut *ptr
};
```

We obtain the thread group ID (`tgid`) for the current execution. This `tgid` is then used to retrieve the corresponding buffer pointer from the `BUFFERS` map. This pointer (`buf_p`) references where the SSL data resides. If this pointer is null, indicating no data or an error, we exit the function early.

Next, we tackle a significant limitation of eBPF programs: their limited stack size, typically capped at around 512 bytes. This limitation means we can't store large data structures like our `Data` structure on the stack. To overcome this, we use the `STORAGE` map, previously mentioned, which is a per-CPU array. This array is designed to store larger data structures. Utilizing `STORAGE` allows us to manage these larger structures both efficiently and safely within the constraints of eBPF programming. In this step, we retrieve a mutable reference to the `Data` structure from `STORAGE`, preparing it for subsequent processing.

In the next section of our function, we focus on populating the `Data` structure with relevant data. This structure is crucial for tracking and analyzing the SSL data we capture.

```rust
// Populate the `Data` structure with the required data.
data.kind = kind;
data.len = retval;
data.comm = bpf_get_current_comm().map_err(|e| e as u32)?;

// Limit the read buffer size to either the actual data size or the predefined maximum buffer size.
// This is a safeguard against reading excessive data and potential buffer overflow.
let buffer_limit = if retval > MAX_BUF_SIZE as i32 {
	MAX_BUF_SIZE as u32
} else {
	retval as u32
};
```

we introduce a safety mechanism to limit the buffer size we read from. The `buffer_limit` variable is set to the smaller of two values: the actual number of bytes returned by the SSL operation (`retval`) or a predefined maximum buffer size (`MAX_BUF_SIZE`). This check is crucial to prevent reading too much data at once, which could lead to buffer overflow issues. By doing this, we ensure that our handling of the data remains within safe and manageable bounds.

We reach a crucial part of our eBPF probe – reading the actual data from user space. Using the helper `bpf_probe_read_user` function, we attempt to copy data from the user space buffer (pointed to by `buf_p`) into our `Data` structure's buffer. The amount of data we try to read is limited by `buffer_limit` to prevent overflows.

```rust
// Perform the actual data reading from user space, which is the crux of data capture in this eBPF probe.
unsafe {
	let ret = bpf_probe_read_user(
		data.buf.as_mut_ptr() as *mut c_void,
		buffer_limit,
		buf_p as *const c_void,
	);

	if ret != 0 {
		info!(&ctx, "bpf_probe_read_user failed: {}", ret);
		return Err(0);
	}
	// Remove buffer entry to clean up and avoid stale data in subsequent operations.
	BUFFERS.remove(&tgid).map_err(|e| e as u8)?;
	EVENTS.output(&ctx, &(*data), 0);
}
```

> The eBPF helper **bpf_probe_read_user** safely attempt to read _size_ bytes from user space address _unsafe_ptr_ and store the data in _dst_.
> 
> The protytype:
> 
> bpf_probe_read_user(void *dst, u32 size, const void *unsafe_ptr)

This operation is performed in an `unsafe` block because it involves raw pointers and direct memory access, which are inherently unsafe in Rust. If `bpf_probe_read_user` returns a non-zero value, it indicates a failure in reading the data. In such cases, we log the error and return early from the function.

Finally, we use the `EVENTS` **PerfEventArray** to output the captured data. The `output` method here sends the contents of our `Data` structure to user space for further processing or analysis. This completes the data capture cycle of our eBPF probe.

So far, we've frequently referred to the `Data` struct, but what exactly does it look like? Since it's a crucial component shared between our application program and kernel space, it's defined in our common component `/https-sniffer-common/src/lib.rs`.

```rust
pub const MAX_BUF_SIZE: usize = 16384;
pub const TASK_COMM_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Read,
    Write,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Data {
    pub kind: Kind,
    pub len: i32,
    pub buf: [u8; MAX_BUF_SIZE],
    pub comm: [u8; TASK_COMM_LEN],
}
```

A key aspect of the `Data` structure to highlight is the `MAX_BUF_SIZE` field. This size is pivotal because OpenSSL functions operate based on SSL/TLS records. TLS protocol specifies a maximum plaintext fragment length of 2^14 (16,384) bytes. Therefore, we've chosen this as our maximum buffer size in the `Data` struct to align with the TLS standard, ensuring our buffer is adequately sized to handle the data segments processed by OpenSSL.

### User-Space Component

In the user-space application `/https-sniffer/src/main.rs`, our first task is to attach our probes to OpenSSL, using the library path we discovered with the `ldd` command. This process is somewhat akin to attaching `kprobes`, but for `uprobes`, we need to specify the eBPF program, the target bin/lib path, and the target function's name.

```rust
const OPEN_SSL_PATH: &str = "/lib/x86_64-linux-gnu/libssl.so.3";

fn attach_openssl(bpf: &mut Bpf, opt: &Opt) -> Result<(), anyhow::Error> {
    // Attach uprobe and uretprobe to SSL_read
    let p_write: &mut UProbe = bpf.program_mut("ssl_write").unwrap().try_into()?;
    p_write.load()?;
    p_write.attach(Some("SSL_write"), 0, OPEN_SSL_PATH, opt.pid)?;

    let p_write_ret: &mut UProbe = bpf.program_mut("ssl_write_ret").unwrap().try_into()?;
    p_write_ret.load()?;
    p_write_ret.attach(Some("SSL_write"), 0, OPEN_SSL_PATH, opt.pid)?;

    // Attach uprobe and uretprobe to SSL_write
    let p_read: &mut UProbe = bpf.program_mut("ssl_read").unwrap().try_into()?;
    p_read.load()?;
    p_read.attach(Some("SSL_read"), 0, OPEN_SSL_PATH, opt.pid)?;

    let p_read_ret: &mut UProbe = bpf.program_mut("ssl_read_ret").unwrap().try_into()?;
    p_read_ret.load()?;
    p_read_ret.attach(Some("SSL_read"), 0, OPEN_SSL_PATH, opt.pid)?;

    Ok(())
}
```

Rust-aya employs a technique to locate the function names within the binary using the symbol table. This approach allows it to pinpoint the exact addresses for the `SSL_read` and `SSL_write` functions, ensuring our `uprobes` are attached correctly.

As we reach the final part of our implementation, we'll focus on handling events from the **PerfEventArray**. In this section, I won't go into extensive detail since the implementation closely follows the rust-aya documentation, particularly the [AsyncPerfEventArray](https://docs.rs/aya/latest/aya/maps/perf/struct.AsyncPerfEventArray.html). This part of the code is crucial for efficiently processing the data captured by our uprobes.

```rust
    // Retrieve the perf event array from the BPF program to read events from it.
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // Calculate the size of the Data structure in bytes.
    let len_of_data = std::mem::size_of::<Data>();
    // Iterate over each online CPU core. For eBPF applications, processing is often done per CPU core.
    for cpu_id in online_cpus()? {
        // open a separate perf buffer for each cpu
        let mut buf = perf_array.open(cpu_id, Some(32))?;

        // process each perf buffer in a separate task
        tokio::spawn(async move {
            // Prepare a set of buffers to store the data read from the perf buffer.
            // Here, 10 buffers are created, each with a capacity equal to the size of the Data structure.
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(len_of_data))
                .collect::<Vec<_>>();

            loop {
                // Attempt to read events from the perf buffer into the prepared buffers.
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        warn!("Error reading events: {}", e);
                        continue;
                    }
                };

                // Iterate over the number of events read. `events.read` indicates how many events were read.
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let data = buf.as_ptr() as *const Data; // Cast the buffer pointer to a Data pointer.
                    info!("{}", unsafe { *data });
                }
            }
        });
    }
```

> An important aspect to note in our code is the use of the value `32` as the second parameter in `perf_array.open`, which represents the `page_count`. This is a crucial factor for Aya when determining the size of the ring buffer. Aya allocates memory for the buffer based on the formula `page size * page_count`. Normally, the page size is around 4KB. 
> 
> Why choose `32` for the `page_count`? It's important to consider that the maximum size of a TLS record is 16KB. To accommodate large communications, we need a sufficiently large ring buffer. While the default value used by rust-aya is `2`, which may be inadequate for our needs, setting `page_count` to `32` ensures we have enough space to handle these larger TLS records data events.

In our application, the primary function is to simply print out the data contained within the `Data` struct. This straightforward approach allows us to directly observe and verify the information captured by our `uprobes`, providing insight into the SSL operations handled by OpenSSL.
### Running our Sniffer

Running our application in one terminal, and then, in another terminal, executing a simple request like `curl https://jsonplaceholder.org/users/1 --http1.1`. Doing so will showcase our application's functionality vividly: all the captured data from this HTTPS request will be displayed in raw, plain text in the terminal running our app. This real-time demonstration is a powerful way to visualize the data capture process and the effectiveness of the uprobes.

```bash
$ RUST_LOG=info cargo xtask run
[2023-12-07T05:35:31Z INFO  http_sniffer] Waiting for Ctrl-C...
[2023-12-07T05:35:40Z INFO  http_sniffer] Kind: Write, Length: 90, Command: curl, Data: GET /users/1 HTTP/1.1
    Host: jsonplaceholder.org
    User-Agent: curl/7.81.0
    Accept: */*
[2023-12-07T05:35:40Z INFO  http_sniffer] Kind: Read, Length: 1323, Command: curl, Data: HTTP/1.1 200 OK
    Date: Thu, 07 Dec 2023 05:35:39 GMT
    Content-Type: application/json; charset=UTF-8
    Transfer-Encoding: chunked
    Connection: keep-alive
    Access-Control-Allow-Origin: *
    Report-To: {"endpoints":[{"url":"https:\/\/a.nel.cloudflare.com\/report\/v3?s=gBHcmc%2Fy3B%2BBaWsG7CgnqKN4LWhn9eeNx5%2Bb2krvmzt2A8fR37f%2FUyAKaQnEIEUOsG5iQLbcAczzOBI3eDLgbaInPlpJVVxVpwqkzMqiqEb%2BJjtAkm95It9GlT9CU4o7CJRNEM8l"}],"group":"cf-nel","max_age":604800}
    NEL: {"success_fraction":0,"report_to":"cf-nel","max_age":604800}
    Vary: Accept-Encoding
    CF-Cache-Status: DYNAMIC
    X-Content-Type-Options: nosniff
    Server: cloudflare
    CF-RAY: 831a6812bce836a9-YYZ
    alt-svc: h3=":443"; ma=86400
{"id":1,"firstname":"John","lastname":"Doe","email":"johndoe@example.com","birthDate":"1973-01-22","login":{"uuid":"1a0eed01-9430-4d68-901f-c0d4c1c3bf22","username":"johndoe","password":"jsonplaceholder.org","md5":"c1328472c5794a25723600f71c1b4586","sha1":"35544a31cc19bd6520af116554873167117f4d94","registered":"2023-01-10T10:03:20.022Z"},"address":{"street":"123 Main Street","suite":"Apt. 4","city":"Anytown","zipcode":"12345-6789","geo":{"lat":"42.1234","lng":"-71.2345"}},"phone":"(555) 555-1234","website":"www.johndoe.com","company":{"name":"ABC Company","catchPhrase":"Innovative solutions for all your needs","bs":"Marketing"}}
[2023-12-07T05:35:40Z INFO http_sniffer] Kind: Read, Length: 5, Command: curl, Data:0 
```

In our demonstration, we include the `--http1.1` flag in the curl command to ensure it uses HTTP/1.1. This detail is important because curl defaults to HTTP/2, which, in our case, would lead to capturing some unreadable data. To illustrate, if we omit this flag, as in `curl https://jsonplaceholder.org/users/1`, the output will be:

```bash
[2023-12-07T05:43:50Z INFO  http_sniffer] Waiting for Ctrl-C...
[2023-12-07T05:44:04Z INFO  http_sniffer] Kind: Write, Length: 24, Command: curl, Data: PRI * HTTP/2.0
[2023-12-07T05:44:04Z INFO  http_sniffer] Kind: Write, Length: 50, Command: curl, Data: )��b��0�A���]!g=��d�z�%�Pë��S*/*
[2023-12-07T05:44:04Z INFO  http_sniffer] Kind: Write, Length: 9, Command: curl, Data: 
&=LtA��P���0p߅g�T*@����Ĭ���U�����+9�J?�������e���t��\��ength: 452, Command: curl, Data: ��a��=�J�/�e@7q���1h�_�u�b
                                                       ��E�rP{d���U�z���؟���v�@�ݹ�TWvb��r�����4hn�}�SM6�C�k@.��N��t���w˫�7I-�����ݎ����l�uɂn�o*,6"���<�@nel�������DR�2$ǫ������{O���I*������~b��n8�?�{���-i[D<��o@�$�d��!#M����L:2^@��RKRVO�ʱ�I�R?�����v�%�Ih�@�$�X?_�y��֜
                                                                                                                   e�@�>�@�     Yɐ��?��4����#��?
[2023-12-07T05:44:04Z INFO  http_sniffer] Kind: Read, Length: 645, Command: curl, Data: |{"id":1,"firstname":"John","lastname":"Doe","email":"johndoe@example.com","birthDate":"1973-01-22","login":{"uuid":"1a0eed01-9430-4d68-901f-c0d4c1c3bf22","username":"johndoe","password":"jsonplaceholder.org","md5":"c1328472c5794a25723600f71c1b4586","sha1":"35544a31cc19bd6520af116554873167117f4d94","registered":"2023-01-10T10:03:20.022Z"},"address":{"street":"123 Main Street","suite":"Apt. 4","city":"Anytown","zipcode":"12345-6789","geo":{"lat":"42.1234","lng":"-71.2345"}},"phone":"(555) 555-1234","website":"www.johndoe.com","company":{"name":"ABC Company","catchPhrase":"Innovative 
```

As evident in our output, while the body of the response is visible, the headers are not; they appear completely unreadable. This is primarily due to HPACK, a compression format used by HTTP/2 for encoding headers. HPACK's specialized compression makes the headers less straightforward to interpret compared to the more readable body content.

All the code discussed is available in my  [repository](https://github.com/douglasmakey/poc-rust-https-sniffer). Feel free to explore, experiment, and comments.
## To conclude

**In summary**, our exploration has demonstrated the power of `uprobes` in capturing network data, specifically within the context of SSL/TLS operations. While we successfully visualized the body content of HTTPS responses, the complexity of HPACK in HTTP/2 highlighted a limitation in reading header information. This journey through kernel and user-space eBPF programming not only showcased the versatility of these tools but also illuminated the intricacies of network communication protocols. Our exploration opens the door to further refinement and adaptation for more complex monitoring scenarios.

Thank you for reading along. This blog is a part of my learning journey and your feedback is highly valued. There's more to explore and share regarding eBPF, so stay tuned for upcoming posts. Your insights and experiences are welcome as we learn and grow together in this domain. **Happy coding!**





