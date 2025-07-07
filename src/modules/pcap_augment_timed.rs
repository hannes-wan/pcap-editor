use std::path::Path;
use std::fs::File;
use pcap_file::{PcapReader, PcapWriter};
use anyhow::{Context, Result, anyhow};
use log::info;

/// 增强PCAP文件的时间分布
/// 
/// # 参数
/// - `input_path`: 输入PCAP文件路径
/// - `output_path`: 输出PCAP文件路径
/// - `multiplier`: 数据包复制倍数
/// 
/// # 功能
/// 1. 保持原始时间跨度不变
/// 2. 复制数据包内容到指定倍数
/// 3. 在时间线上均匀分布复制包
pub fn pcap_augment_timed(
    input_path: &str,
    output_path: &str,
    multiplier: usize,
) -> Result<()> {
    // 验证倍数参数
    if multiplier < 2 {
        anyhow::bail!("复制倍数必须大于1，当前为: {}", multiplier);
    }

    // 打开输入文件
    let in_file = File::open(Path::new(input_path))
        .with_context(|| format!("无法打开输入文件: {}", input_path))?;
    let mut pcap_reader = PcapReader::new(in_file)
        .map_err(|e| anyhow!("无效的PCAP文件格式: {}", e))?;

    // 创建输出文件
    let out_file = File::create(Path::new(output_path))
        .with_context(|| format!("无法创建极出文件: {}", output_path))?;
    
    // 正确创建PcapWriter
    let header = pcap_reader.header.clone();
    let mut pcap_writer = PcapWriter::with_header(header, out_file)
        .map_err(|e| anyhow!("创建PCAP写入器失败: {}", e))?;

    // 读取所有原始包
    let mut original_packets = Vec::new();
    while let Some(packet) = pcap_reader.next() {
        original_packets.push(packet);
    }

    // 检查是否有足够的数据包
    if original_packets.is_empty() {
        anyhow::bail!("输入文件不包含任何数据包");
    }

    // 获取第一个包和最后一个包的时间戳
    let first_packet = &original_packets[0];
    let last_packet = original_packets.last().unwrap();
    
    // 计算原始时间跨度（纳秒）
    let first_sec = first_packet.header.ts_sec;
    let first_usec = first_packet.header.ts_usec;
    let last_sec = last_packet.header.ts_sec;
    let last_usec = last_packet.header.ts_usec;
    
    // 转换为纳秒精度
    let first_ns = (first_sec as u128) * 1_000_000_000 + first_usec as u128 * 1000;
    let last_ns = (last_sec as u128) * 1_000_000_000 + last_usec as u128 * 1000;
    
    let total_duration_ns = last_ns - first_ns;
    
    // 计算目标包数
    let target_packet_count = original_packets.len() * multiplier;
    
    // 计算理想间隔（纳秒）
    let ideal_interval_ns = if target_packet_count > 1 {
        total_duration_ns / (target_packet_count - 1) as u128
    } else {
        0
    };

    // 创建新包数组
    let mut new_packets = Vec::with_capacity(target_packet_count);
    
    // 按顺序生成新包
    for i in 0..target_packet_count {
        // 计算新包的时间戳（纳秒）
        let new_ns = first_ns + ideal_interval_ns * i as u128;
        
        // 转换为秒和纳秒
        let new_sec = (new_ns / 1_000_000_000) as u32;
        let new_ns_residual = (new_ns % 1_000_000_000) as u32;
        let new_usec = new_ns_residual / 1000; // 转换为微秒
        
        // 选择原始包（循环分配）
        let orig_index = i % original_packets.len();
        let mut new_packet = original_packets[orig_index].clone();
        
        // 设置新时间戳
        new_packet.header.ts_sec = new_sec;
        new_packet.header.ts_usec = new_usec;
        
        new_packets.push(new_packet);
    }

    // 保存新包数量
    let new_packet_count = new_packets.len();  // 新增行

    // 写入所有新包
    for packet in new_packets {
        pcap_writer.write_packet(&packet)
            .map_err(|e| anyhow!("写入包失败: {}", e))?;
    }

    info!(
        "成功生成增强文件: 原始包数={}, 复制倍数={}, 总包数={}",
        original_packets.len(),
        multiplier,
        new_packet_count  // 修改为临时变量
    );

    Ok(())
}