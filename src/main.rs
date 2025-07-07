// src/main.rs
use clap::{Parser, Subcommand};
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::path::PathBuf;

mod modules;

/// PCAP工具箱 - 多功能网络数据包处理工具
#[derive(Parser)]
#[command(name = "pcap-editor")]
#[command(author = "hannes_wan <hg3328762@qq.com>")]
#[command(version = "1.0.0")]
#[command(
    about = r#"

██████╗  ██████╗ █████╗ ██████╗     ███████╗██████╗ ██╗██████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝██║     ███████║██████╔╝    █████╗  ██║  ██║██║██║  ██║██║  ██║█████╗  ██████╔╝
██╔═══╝ ██║     ██╔══██║██╔═══╝     ██╔══╝  ██║  ██║██║██║  ██║██║  ██║██╔══╝  ██╔══██╗
██║     ╚██████╗██║  ██║██║         ███████╗██████╔╝██║██████╔╝██████╔╝███████╗██║  ██║
╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝         ╚══════╝╚═════╝ ╚═╝╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
"#,
    long_about = None,
)]
struct Cli {
    /// 日志级别 [trace|debug|info|warn|error|off]
    #[arg(short, long, default_value = "info")]
    log_level: String,
    
    /// 要执行的操作
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 压缩PCAP文件时间轴
    TimeCompress {
        /// 输入PCAP文件路径
        input: PathBuf,
        
        /// 输出PCAP文件路径
        output: PathBuf,
        
        /// 压缩因子 (大于1.0)
        #[arg(short, long)]
        factor: f64,
    },
    
    /// 拉伸PCAP文件时间轴
    TimeStretch {
        /// 输入PCAP文件路径
        input: PathBuf,
        
        /// 输出PCAP文件路径
        output: PathBuf,
        
        /// 拉伸因子 (大于0.0)
        #[arg(short, long)]
        factor: f64,
    },
    
    /// 稀释PCAP文件 (减少数据包数量)
    Dilute {
        /// 输入PCAP文件路径
        input: PathBuf,
        
        /// 输出PCAP文件路径
        output: PathBuf,
        
        /// 稀释因子 (大于1的整数)
        #[arg(short, long)]
        factor: usize,
    },
    
    /// 增强PCAP文件 (复制数据包)
    Augment {
        /// 输入PCAP文件路径
        input: PathBuf,
        
        /// 输出PCAP文件路径
        output: PathBuf,
        
        /// 复制倍数 (大于1的整数)
        #[arg(short, long)]
        factor: usize,
    },
    
    /// 检测PCAP文件中的乱序数据包
    DisorderDetect {
        /// 输入PCAP文件路径
        input: PathBuf,
    },
    
    /// 比较两个PCAP文件的内容差异
    Compare {
        /// 基准PCAP文件路径
        reference: PathBuf,
        
        /// 对比PCAP文件路径
        comparison: PathBuf,

        #[arg(long)]
        ignore_timestamp: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    // 初始化日志
    let log_level = match cli.log_level.as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,
        _ => LevelFilter::Info,
    };
    
    SimpleLogger::new()
        .with_level(log_level)
        .init()
        .unwrap();
    
    // 执行命令
    match cli.command {
        Commands::TimeCompress { input, output, factor } => {
            modules::pcap_time_reducer::pcap_time_compressor(
                input.to_str().unwrap(),
                output.to_str().unwrap(),
                factor
            )
        },
        
        Commands::TimeStretch { input, output, factor } => {
            modules::pcap_time_dilator::pcap_time_dilator(
                input.to_str().unwrap(),
                output.to_str().unwrap(),
                factor
            )
        },
        
        Commands::Dilute { input, output, factor } => {
            modules::pcap_dilute_timed::pcap_dilute_timed(
                input.to_str().unwrap(),
                output.to_str().unwrap(),
                factor
            )
        },
        
        Commands::Augment { input, output, factor } => {
            modules::pcap_augment_timed::pcap_augment_timed(
                input.to_str().unwrap(),
                output.to_str().unwrap(),
                factor
            )
        },
        
        Commands::DisorderDetect { input } => {
            modules::pcap_shuffle_tester::detect_pcap_disorder(
                input.to_str().unwrap()
            )
        },
        
        Commands::Compare { reference, comparison, ignore_timestamp } => {
            modules::pcap_comparative_analyzer::compare_ordered_pcaps(
                reference.to_str().unwrap(),
                comparison.to_str().unwrap(),
                ignore_timestamp  // 传递新参数
            )
        },
    }
}