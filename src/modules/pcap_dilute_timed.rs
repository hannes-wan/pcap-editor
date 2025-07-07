use std::path::Path;
use std::fs::File;
use pcap_file::{PcapReader, PcapWriter};
use anyhow::{Context, Result, anyhow};
use log::info;

/// 稀释PCAP文件的时间分布
/// 
/// # 参数
/// - `input_path`: 输入PCAP文件路径
/// - `output_path`: 输出PCAP文件路径
/// - `dilution_factor`: 稀释因子(大于1的整数)
/// 
/// # 功能
/// 1. 保持原始时间跨度不变
/// 2. 按稀释因子减少数据包数量
/// 3. 在时间线上均匀分布保留的数据包
pub fn pcap_dilute_timed(
    input_path: &str,
    output_path: &str,
    dilution_factor: usize,
) -> Result<()> {
    // 验证稀释因子
    if dilution_factor < 2 {
        anyhow::bail!("稀释因子必须大于1，当前为: {}", dilution_factor);
    }

    // 打开输入文件
    let in_file = File::open(Path::new(input_path))
        .with_context(|| format!("无法打开输入文件: {}", input_path))?;
    let mut pcap_reader = PcapReader::new(in_file)
        .map_err(|e| anyhow!("无效的PCAP文件格式: {}", e))?;

    // 创建输出文件
    let out_file = File::create(Path::new(output_path))
        .with_context(|| format!("无法创建输出文件: {}", output_path))?;
    
    // 正确创建PcapWriter
    let header = pcap_reader.header.clone();
    let mut pcap_writer = PcapWriter::with_header(header, out_file) // 参数顺序修正
        .map_err(|e| anyhow!("创建PCAP写入器失败: {}", e))?;

    // 读取所有原始包并计算时间信息
    let mut original_packets = Vec::new();
    let mut first_timestamp = None;
    let mut last_timestamp = None;
    
    while let Some(packet) = pcap_reader.next() {
        // 更新首尾时间戳
        if first_timestamp.is_none() {
            first_timestamp = Some((packet.header.ts_sec, packet.header.ts_usec));
        }
        last_timestamp = Some((packet.header.ts_sec, packet.header.ts_usec));
        
        original_packets.push(packet);
    }

    // 检查是否有足够的数据包
    if original_packets.is_empty() {
        anyhow::bail!("输入文件不包含任何数据包");
    }
    if original_packets.len() < dilution_factor {
        anyhow::bail!(
            "数据包数量({})少于稀释因子({})",
            original_packets.len(),
            dilution_factor
        );
    }

    // 解包时间戳
    let (first_sec, first_usec) = first_timestamp.unwrap();
    let (last_sec, last_usec) = last_timestamp.unwrap();
    
    // 计算原始时间跨度（微秒）
    let total_duration_us = ((last_sec as i64 - first_sec as i64) * 1_000_000) 
        + (last_usec as i64 - first_usec as i64);
    
    // 计算目标数据包数量
    let target_packet_count = original_packets.len() / dilution_factor;
    
    // 计算理想间隔（微秒）
    let ideal_interval_us = total_duration_us / target_packet_count as i64;
    
    // 创建时间线位置
    let mut current_target_sec = first_sec;
    let mut current_target_usec = first_usec;
    let mut packet_index = 0;
    let mut packets_written = 0;
    
    // 遍历并选择最接近目标时间点的包
    for i in 0..target_packet_count {
        // 计算下一个目标时间点（第一个包使用原始时间戳）
        if i > 0 {
            // 计算新的微秒值
            let mut new_usec = current_target_usec as i64 + ideal_interval_us;
            let mut new_sec = current_target_sec as i64;
            
            // 处理微秒溢出
            if new_usec >= 1_000_000 {
                new_sec += new_usec / 1_000_000;
                new_usec %= 1_000_000;
            }
            
            current_target_sec = new_sec as u32;
            current_target_usec = new_usec as u32;
        }
        
        // 查找最接近目标时间点的包
        let mut best_index = packet_index;
        let mut best_diff = i64::MAX;
        
        // 从当前位置向后搜索（提高效率）
        for j in packet_index..original_packets.len() {
            let packet = &original_packets[j];
            
            // 计算时间差（微秒）
            let sec_diff = packet.header.ts_sec as i64 - current_target_sec as i64;
            let usec_diff = packet.header.ts_usec as i64 - current_target_usec as i64;
            let total_diff = (sec_diff * 1_000_000) + usec_diff;
            
            // 找到更接近的包
            if total_diff.abs() < best_diff {
                best_diff = total_diff.abs();
                best_index = j;
            }
            // 如果时间差开始增大，提前终止搜索
            else if total_diff.abs() > best_diff {
                break;
            }
        }
        
        // 更新下一个搜索起点
        packet_index = best_index + 1;
        
        // 写入选中的包（保持原始时间戳）
        pcap_writer.write_packet(&original_packets[best_index])
            .map_err(|e| anyhow!("写入包失败: {}", e))?;
        packets_written += 1;
    }

    info!(
        "成功生成稀释文件: 原始包数={}, 稀释因子={}, 保留包数={}",
        original_packets.len(),
        dilution_factor,
        packets_written
    );

    Ok(())
}