use aya::maps::AsyncPerfEventArray;
use aya::programs::UProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use https_sniffer_common::Data;
use log::{debug, info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

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

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/https-sniffer"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/https-sniffer"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Attach uprobe and uretprobe to OpenSSL.
    attach_openssl(&mut bpf, &opt)?;

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

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
