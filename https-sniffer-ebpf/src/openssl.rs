use aya_bpf::{
    cty::c_void,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, gen::bpf_probe_read_user},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use https_sniffer_common::{Data, Kind, MAX_BUF_SIZE};

#[map]
static mut STORAGE: PerCpuArray<Data> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut EVENTS: PerfEventArray<Data> = PerfEventArray::with_max_entries(1024, 0);

#[map]
static mut BUFFERS: HashMap<u32, *const u8> = HashMap::with_max_entries(1024, 0);

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

// `try_ssl` function is an eBPF probe for capturing SSL data.
fn try_ssl(ctx: ProbeContext) -> Result<u32, u32> {
    let tgid: u32 = bpf_get_current_pid_tgid() as u32;
    // Get the buffer pointer (second argument of the probed function) from the context.
    let buf_p: *const u8 = ctx.arg(1).ok_or(0_u32)?;
    // Insert the buffer pointer into the `BUFFERS` map for the current process/thread group.
    unsafe { BUFFERS.insert(&tgid, &buf_p, 0).map_err(|e| e as u8)? };
    Ok(0)
}

// `try_ssl_ret` function is an eBPF probe for handling the return value of an SSL function.
fn try_ssl_ret(ctx: ProbeContext, kind: Kind) -> Result<u32, u32> {
    // `retval` represents the number of bytes actually read from the TLS/SSL connection.
    // This value is crucial as it indicates the success of the read operation and the size of the data read.
    let retval: i32 = ctx.ret().ok_or(0u32)?;
    if retval <= 0 {
        return Ok(0);
    }

    let tgid: u32 = bpf_get_current_pid_tgid() as u32;
    // Retrieve the buffer pointer from the `BUFFERS` map for the current process/thread group.
    let buf_p = unsafe {
        let ptr = BUFFERS.get(&tgid).ok_or(0_u32)?;
        *ptr
    };

    if buf_p.is_null() {
        return Ok(0);
    }

    // In eBPF programs, stack size is limited (typically to 512 bytes).
    // Therefore, larger data structures like `Data` cannot be allocated on the stack.
    // To work around this limitation, we use a per-CPU array (`STORAGE`) to store `Data` structures.
    // This approach allows handling larger data structures efficiently and safely.
    // Here, we obtain a mutable reference to the `Data` structure stored in `STORAGE` for further processing.
    let data = unsafe {
        let ptr = STORAGE.get_ptr_mut(0).ok_or(0_u32)?;
        &mut *ptr
    };

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

        // Remove the buffer entry to clean up and avoid stale data in subsequent operations.
        BUFFERS.remove(&tgid).map_err(|e| e as u8)?;
        // Emit the captured data as an event, enabling further analysis or monitoring.
        // This is typically where the eBPF program interfaces with external observers or tools.
        EVENTS.output(&ctx, &(*data), 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
