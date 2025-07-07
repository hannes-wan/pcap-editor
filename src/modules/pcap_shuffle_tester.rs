use std::path::Path;
use std::fs::File;
use std::io::{Seek}; // 添加 Seek trait 导入
use pcap_file::{PcapReader};
use log::{error, info, warn};
use anyhow::{Context, Result, anyhow};
use std::time::Duration;

pub fn detect_pcap_disorder(input_path: &str) -> Result<()> {
    let file = File::open(Path::new(input_path))
        .with_context(|| format!("无法打开文件: {}", input_path))?;
    
    let mut pcap_reader = PcapReader::new(file)
        .map_err(|e| anyhow!("无效的PCAP文件格式: {}", e))?;

    let mut prev_timestamp: Option<Duration> = None;
    let mut disorder_count = 0;
    let mut packet_count = 0;
    let mut read_errors = 0;

    while let Some(packet) = pcap_reader.next() {
        packet_count += 1;
        
        // 从包头获取时间戳
        let header = &packet.header;
        let current_timestamp = Duration::new(
            header.ts_sec as u64,    // 秒部分
            header.ts_usec * 1000    // 微秒转纳秒
        );
        
        if let Some(prev_ts) = prev_timestamp {
            if current_timestamp < prev_ts {
                disorder_count += 1;
                
                let time_diff = prev_ts - current_timestamp;
                let time_diff_sec = time_diff.as_secs_f64();
                
                warn!(
                    "乱序包 #{}: 时间戳 {}.{:09} < 前包 {}.{:09} (差值: {:.9}秒)",
                    packet_count,
                    current_timestamp.as_secs(),
                    current_timestamp.subsec_nanos(),
                    prev_ts.as_secs(),
                    prev_ts.subsec_nanos(),
                    time_diff_sec
                );
            }
        }
        prev_timestamp = Some(current_timestamp);
    }

    // 检测是否提前结束
    if let Ok(metadata) = std::fs::metadata(input_path) {
        let file_size = metadata.len();
        
        // 修复点：使用 Seek trait 的方法
        let mut reader = pcap_reader.into_reader();
        let pos = reader.stream_position()?; // 现在可以调用 stream_position()
        
        if pos < file_size {
            warn!(
                "⚠️ 文件未完全读取: 已读取 {} 字节/总计 {} 字节 ({} 个数据包)",
                pos, file_size, packet_count
            );
            read_errors += 1;
        }
    }

    // 结果报告（保持不变）
    if disorder_count == 0 && read_errors == 0 {
        info!("✅ 未检测到乱序包 (共 {} 个数据包)", packet_count);
    } else {
        if disorder_count > 0 {
            error!("⚠️ 检测到 {} 个乱序包", disorder_count);
        }
        if read_errors > 0 {
            error!("⚠️ 检测到 {} 个读取错误", read_errors);
        }
        info!("共处理 {} 个数据包", packet_count);
    }
    
    Ok(())
}