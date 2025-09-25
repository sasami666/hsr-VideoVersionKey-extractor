use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::panic;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use chrono::Local;
use clap::Parser;
use reliquary::network::{GamePacket, GameSniffer};
use tracing::{error, info, instrument, warn};
use tracing_subscriber::{prelude::*, EnvFilter, Registry};

mod capture;
mod protos;
use protos::GetVideoVersionKeyScRsp::GetVideoVersionKeyScRsp;

// From PacketIds.json
const GET_VIDEO_VERSION_KEY_SC_RSP: u16 = 18;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to output .json file to.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Read packets from .pcap file instead of capturing live packets
    #[cfg(feature = "pcap")]
    #[arg(long)]
    pcap: Option<PathBuf>,

    /// Read packets from .etl file instead of capturing live packets
    #[cfg(feature = "pktmon")]
    #[arg(long)]
    etl: Option<PathBuf>,

    /// How long to wait in seconds until timeout is triggered for live captures
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

#[derive(Debug, Clone)]
enum CaptureMode {
    Live,
    #[cfg(feature = "pcap")]
    Pcap(PathBuf),
    #[cfg(feature = "pktmon")]
    Etl(PathBuf),
}

impl CaptureMode {
    fn from_args(args: &Args) -> Self {
        #[cfg(feature = "pcap")]
        if let Some(path) = &args.pcap {
            return CaptureMode::Pcap(path.clone());
        }

        #[cfg(feature = "pktmon")]
        if let Some(path) = &args.etl {
            return CaptureMode::Etl(path.clone());
        }

        CaptureMode::Live
    }
}

fn main() {
    color_eyre::install().unwrap();
    let args = Args::parse();
    tracing_init();

    if let Err(_) = panic::catch_unwind(move || {
        let keys_str = include_str!("../keys/hsr.json");
        let initial_keys_str: HashMap<u32, String> =
            serde_json::from_str(keys_str).expect("Failed to parse keys.json");
        let mut initial_keys = HashMap::new();
        for (k, v) in initial_keys_str {
            initial_keys.insert(
                k,
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v).unwrap(),
            );
        }

        let sniffer = GameSniffer::new().set_initial_keys(initial_keys);

        let capture_mode = CaptureMode::from_args(&args);

        let video_keys_data = match capture_mode {
            CaptureMode::Live => live_capture(&args, sniffer),
            #[cfg(feature = "pcap")]
            CaptureMode::Pcap(path) => capture_from_pcap(sniffer, path),
            #[cfg(feature = "pktmon")]
            CaptureMode::Etl(path) => capture_from_etl(sniffer, path),
        };

        if let Some(data) = video_keys_data {
            let file_path = args.output.unwrap_or_else(|| {
                let date = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
                PathBuf::from(format!("output_{}.json", date))
            });

            info!("Writing video keys to {}", file_path.display());
            let file = File::create(&file_path).expect("Failed to create output file");
            serde_json::to_writer_pretty(file, &data).expect("Failed to write JSON to file");
            info!("Successfully saved video keys.");
        } else {
            warn!("No video key data was captured. No file written.");
        }
    }) {
        error!("The application panicked. This is a bug.");
    }

    info!("Press Enter to close...");
    std::io::stdin().read_line(&mut String::new()).unwrap();
}

fn tracing_init() {
    let env_filter = EnvFilter::builder()
        .with_default_directive("info".parse().unwrap())
        .from_env_lossy();

    let subscriber =
        Registry::default().with(tracing_subscriber::fmt::layer().with_filter(env_filter));
    tracing::subscriber::set_global_default(subscriber).expect("unable to set up logging");
}

#[instrument(skip_all)]
fn live_capture(args: &Args, mut sniffer: GameSniffer) -> Option<GetVideoVersionKeyScRsp> {
    let abort_signal = std::sync::Arc::new(AtomicBool::new(false));

    let rx = {
        #[cfg(all(windows, feature = "pktmon"))]
        {
            if unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().into() } {
                capture::listen_on_all(capture::pktmon::PktmonBackend, abort_signal.clone())
            } else {
                prompt_for_admin();
                return None;
            }
        }
        #[cfg(all(windows, feature = "pcap", not(feature = "pktmon")))]
        {
            capture::listen_on_all(capture::pcap::PcapBackend, abort_signal.clone())
        }
        #[cfg(not(windows))]
        {
            capture::listen_on_all(capture::pcap::PcapBackend, abort_signal.clone())
        }
    };

    let (rx, join_handles) = rx.expect("Failed to start packet capture");

    info!("Starting live capture... Please start the game and log in.");
    info!(
        "Waiting for video key data with a timeout of {} seconds...",
        args.timeout
    );

    let mut result = None;

    'recv: loop {
        match rx.recv_timeout(Duration::from_secs(args.timeout)) {
            Ok(packet) => {
                if let Ok(packets) = sniffer.receive_packet(packet.data) {
                    for packet in packets {
                        if let GamePacket::Commands(Ok(command)) = packet {
                            if command.command_id == GET_VIDEO_VERSION_KEY_SC_RSP {
                                info!("Found GetVideoVersionKeyScRsp packet!");
                                match command.parse_proto::<GetVideoVersionKeyScRsp>() {
                                    Ok(data) => {
                                        result = Some(data);
                                    }
                                    Err(e) => warn!("Failed to parse proto: {}", e),
                                }
                                break 'recv;
                            }
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                warn!("Capture timed out. No video key packet received.");
                break 'recv;
            }
            Err(RecvTimeoutError::Disconnected) => {
                error!("Packet channel disconnected.");
                break 'recv;
            }
        }
    }

    abort_signal.store(true, Ordering::Relaxed);
    for handle in join_handles {
        handle.join().expect("Failed to join capture thread");
    }
    result
}

#[cfg(feature = "pcap")]
#[instrument(skip_all)]
fn capture_from_pcap(
    mut sniffer: GameSniffer,
    pcap_path: PathBuf,
) -> Option<GetVideoVersionKeyScRsp> {
    info!("Capturing from pcap file: {}", pcap_path.display());
    let mut capture = pcap::Capture::from_file(&pcap_path).expect("could not read pcap file");
    capture
        .filter("udp portrange 23301-23302", true)
        .unwrap();

    while let Ok(packet) = capture.next_packet() {
        if let Ok(packets) = sniffer.receive_packet(packet.data.to_vec()) {
            for packet in packets {
                if let GamePacket::Commands(Ok(command)) = packet {
                    if command.command_id == GET_VIDEO_VERSION_KEY_SC_RSP {
                        info!("Found GetVideoVersionKeyScRsp packet in pcap!");
                        return match command.parse_proto::<GetVideoVersionKeyScRsp>() {
                            Ok(data) => Some(data),
                            Err(e) => {
                                warn!("Failed to parse proto: {}", e);
                                None
                            }
                        };
                    }
                }
            }
        }
    }
    warn!("No video key packet found in the pcap file.");
    None
}

#[cfg(feature = "pktmon")]
#[instrument(skip_all)]
fn capture_from_etl(
    mut sniffer: GameSniffer,
    etl_path: PathBuf,
) -> Option<GetVideoVersionKeyScRsp> {
    info!("Capturing from etl file: {}", etl_path.display());
    let mut capture = pktmon::EtlCapture::new(&etl_path).expect("could not read etl file");
    capture.start().expect("could not start etl capture");

    while let Ok(packet) = capture.next_packet() {
        if let pktmon::PacketPayload::Ethernet(payload) = packet.payload {
            if let Ok(packets) = sniffer.receive_packet(payload) {
                for packet in packets {
                    if let GamePacket::Commands(Ok(command)) = packet {
                        if command.command_id == GET_VIDEO_VERSION_KEY_SC_RSP {
                            info!("Found GetVideoVersionKeyScRsp packet in etl!");
                            return match command.parse_proto::<GetVideoVersionKeyScRsp>() {
                                Ok(data) => Some(data),
                                Err(e) => {
                                    warn!("Failed to parse proto: {}", e);
                                    None
                                }
                            };
                        }
                    }
                }
            }
        }
    }
    warn!("No video key packet found in the etl file.");
    None
}

#[cfg(all(windows, feature = "pktmon"))]
fn prompt_for_admin() {
    fn confirm(msg: &str) -> bool {
        use std::io::Write;
        print!("{}", msg);
        if std::io::stdout().flush().is_err() {
            return false;
        }
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            return false;
        }
        input = input.trim().to_lowercase();
        input.starts_with("y") || input.is_empty()
    }

    println!();
    println!("===========================================================================================================");
    println!("                       Administrative privileges are required to capture packets");
    println!("===========================================================================================================");
    println!();
    println!("This tool uses PacketMonitor (pktmon), which requires running as an administrator to capture network traffic.");
    println!();
    if confirm("Would you like to restart the application with elevated privileges? (Y/n): ") {
        if let Err(e) = escalate_to_admin() {
            error!("Failed to escalate privileges: {}", e);
        }
    }
}

#[cfg(windows)]
fn escalate_to_admin() -> Result<(), Box<dyn std::error::Error>> {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::w;
    use windows::core::PCWSTR;
    use windows::Win32::System::Console::GetConsoleWindow;
    use windows::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetWindow, GW_OWNER, SW_SHOWNORMAL};

    let args_str = env::args().skip(1).collect::<Vec<_>>().join(" ");
    let exe_path: Vec<u16> = env::current_exe()?
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let args: Vec<u16> = args_str.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let console_window = GetConsoleWindow();
        let owner_window = GetWindow(console_window, GW_OWNER);
        let hwnd = if owner_window.0 == 0 {
            console_window
        } else {
            owner_window
        };
        
        let mut options = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            hwnd,
            lpVerb: w!("runas"),
            lpFile: PCWSTR(exe_path.as_ptr()),
            lpParameters: PCWSTR(args.as_ptr()),
            nShow: SW_SHOWNORMAL.0,
            ..Default::default()
        };
        ShellExecuteExW(&mut options)?;
    };

    std::process::exit(0);
}