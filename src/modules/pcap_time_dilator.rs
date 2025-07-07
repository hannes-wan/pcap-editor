use std::path::Path;
use std::fs::File;
use pcap_file::{PcapReader, PcapWriter};
use anyhow::{Context, Result, anyhow};
use log::info;

pub fn pcap_time_dilator(
    input_path: &str,
    output_path: &str,
    time_factor: f64,
) -> Result<()> {
    // 验证时间因子
    if time_factor <= 0.0 {
        anyhow::bail!("时间拉伸因子必须大于0，当前为: {}", time_factor);
    }

    // 打开输入文件
    let in_file = File::open(Path::new(input_path))
        .with_context(|| format!("无法打开输入文件: {}", input_path))?;
    let mut pcap_reader = PcapReader::new(in_file)
        .map_err(|e| anyhow!("无效的PCAP文件格式: {}", e))?;

    // 创建输出文件
    let out_file = File::create(Path::new(output_path))
        .with_context(|| format!("无法创建输出文件: {}", output_path))?;
    
    let header = pcap_reader.header.clone();
    let mut pcap_writer = PcapWriter::with_header(header, out_file) // 参数顺序修正
        .map_err(|e| anyhow!("创建PCAP写入器失败: {}", e))?;

    // 使用迭代器的 next() 方法
    let first_packet = match pcap_reader.next() {
        Some(packet) => packet,
        None => anyhow::bail!("输入文件不包含任何数据包"),
    };
    
    // 获取基准时间戳（从包头获取）
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
        
        // 应用时间拉伸因子
        let stretched_micros = (total_micros as f64 * time_factor).round() as i64;
        
        // 计算新的绝对极时间戳
        let new_sec = (base_sec as i64 + stretched_micros / 1_000_000) as u32;
        let new_usec = (base_usec as i64 + stretched_micros % 1_000_000) as u32;
        
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
        "成功生成时间拉伸文件: 原始包数={}, 时间因子={}, 输出时间跨度={:.2}x",
        packet_count,
        time_factor,
        time_factor
    );

    Ok(())
}