use std::path::Path;
use std::fs::File;
use pcap_file::{PcapReader, PcapWriter};
use anyhow::{Context, Result, anyhow};
use log::{info};

/// 压缩PCAP文件的时间轴
/// 
/// # 参数
/// - `input_path`: 输入PCAP文件路径
/// - `output_path`: 输出PCAP文件路径
/// - `compression_factor`: 时间压缩因子(大于1的浮点数)
/// 
/// # 功能
/// 1. 保持所有数据包内容不变
/// 2. 将所有时间戳按指定倍率压缩
/// 3. 保持时间戳的相对顺序和比例关系
pub fn pcap_time_compressor(
    input_path: &str,
    output_path: &str,
    compression_factor: f64,
) -> Result<()> {
    // 验证压缩因子
    if compression_factor <= 1.0 {
        anyhow::bail!("时间压缩因子必须大于1，当前为: {}", compression_factor);
    }

    // 打开输入文件
    let in_file = File::open(Path::new(input_path))
        .with_context(|| format!("无法打开输入文件: {}", input_path))?;
    let mut pcap_reader = PcapReader::new(in_file)
        .map_err(|e| anyhow!("无效的PCAP文件格式: {}", e))?;

    // 创建输出文件
    let out_file = File::create(Path::new(output_path))
        .with_context(|| format!("无法创建输出文件: {}", output_path))?;
    
    // 修复点：正确创建PcapWriter
    let header = pcap_reader.header.clone();
    let mut pcap_writer = PcapWriter::with_header(header, out_file) // 参数顺序修正
        .map_err(|e| anyhow!("创建PCAP写入器失败: {}", e))?;

    // 读取第一个包作为时间基准
    let first_packet = match pcap_reader.next() {
        Some(packet) => packet,
        None => anyhow::bail!("输入文件不包含任何数据包"),
    };
    
    // 获取基准时间戳（秒和微秒）
    let base_sec = first_packet.header.ts_sec;
    let base_usec = first_packet.header.ts_usec;
    
    // 写入第一个包（时间戳不变）
    pcap_writer.write_packet(&first_packet)
        .map_err(|e| anyhow!("写入第一个包失败: {}", e))?;
    let mut packet_count = 1;

    // 处理后续包
    while let Some(packet) = pcap_reader.next() {
        let mut packet = packet;
        packet_count += 1;
        
        // 计算相对于基准的时间差（微秒）
        let time_diff_sec = packet.header.ts_sec as i64 - base_sec as i64;
        let time_diff_usec = packet.header.ts_usec as i64 - base_usec as i64;
        let total_micros = time_diff_sec * 1_000_000 + time_diff_usec;
        
        // 应用时间压缩因子
        let compressed_micros = (total_micros as f64 / compression_factor).round() as i64;
        
        // 计算新的绝对时间戳
        let new_sec = (base_sec as i64 + compressed_micros / 1_000_000) as u32;
        let new_usec = (base_usec as i64 + compressed_micros % 1_000_000) as u32;
        
        // 修正可能的时间溢出
        let adjusted_sec = new_sec + new_usec / 1_000_000;
        let adjusted_usec = new_usec % 1_000_000;
        
        // 更新包的时间戳
        packet.header.ts_sec = adjusted_sec;
        packet.header.ts_usec = adjusted_usec;
        
        // 写入修改后的包
        pcap_writer.write_packet(&packet)
            .map_err(|e| anyhow!("写入包#{}失败: {}", packet_count, e))?;
    }

    info!(
        "成功生成时间压缩文件: 原始包数={}, 压缩因子={}, 输出时间跨度={:.2}x",
        packet_count,
        compression_factor,
        1.0 / compression_factor
    );

    Ok(())
}