use std::path::Path;
use std::fs::File;
use pcap_file::PcapReader;
use seahash::SeaHasher;
use std::hash::Hasher;
use anyhow::{Context, Result, anyhow};

/// 比较两个PCAP文件的内容差异（顺序大致相同）
/// 
/// # 参数
/// - `pcap1_path`: 基准PCAP文件路径
/// - `pcap2_path`: 对比PCAP文件路径
/// 
/// # 输出
/// - 打印pcap2相对于pcap1的丢失包和多余包
pub fn compare_ordered_pcaps(
    pcap1_path: &str,
    pcap2_path: &str,
    ignore_timestamp: bool,
) -> Result<()> {
    // 打开文件
    let file1 = File::open(Path::new(pcap1_path))
        .with_context(|| format!("无法打开基准文件: {}", pcap1_path))?;
    let mut pcap1_reader = PcapReader::new(file1)
        .map_err(|e| anyhow!("无效的PCAP文件格式 (基准文件): {}", e))?;
    
    let file2 = File::open(Path::new(pcap2_path))
        .with_context(|| format!("无法打开对比文件: {}", pcap2_path))?;
    let mut pcap2_reader = PcapReader::new(file2)
        .map_err(|e| anyhow!("无效的PCAP文件格式 (对比文件): {}", e))?;

    // 读取所有包并计算哈希
    let packets1 = read_and_hash_packets(&mut pcap1_reader, ignore_timestamp)?;
    let packets2 = read_and_hash_packets(&mut pcap2_reader, ignore_timestamp)?;
    
    // 初始化变量
    let mut i = 0; // pcap1索引
    let mut j = 0; // pcap2索引
    let mut missing_packets = Vec::new(); // 丢失包
    let mut extra_packets = Vec::new();   // 多余包
    
    // 主比较循环
    while i < packets1.len() && j < packets2.len() {
        // 当前包匹配
        if packets1[i].hash == packets2[j].hash {
            i += 1;
            j += 1;
            continue;
        }
        
        // 查找下一个匹配点
        let mut found_match = false;
        
        // 向前查找匹配点（最多100个包）
        let max_lookahead = 100;
        let max_i = (i + max_lookahead).min(packets1.len());
        let max_j = (j + max_lookahead).min(packets2.len());
        
        // 尝试在pcap2中查找当前pcap1包
        for k in j..max_j {
            if packets1[i].hash == packets2[k].hash {
                // j到k之间的包是多余包
                for idx in j..k {
                    extra_packets.push((idx, packets2[idx].clone()));
                }
                j = k + 1;
                i += 1;
                found_match = true;
                break;
            }
        }
        
        if found_match {
            continue;
        }
        
        // 尝试在pcap1中查找当前pcap2包
        for k in i..max_i {
            if packets1[k].hash == packets2[j].hash {
                // i到k之间的包是丢失包
                for idx in i..k {
                    missing_packets.push((idx, packets1[idx].clone()));
                }
                i = k + 1;
                j += 1;
                found_match = true;
                break;
            }
        }
        
        if found_match {
            continue;
        }
        
        // 未找到匹配 - 记录差异
        missing_packets.push((i, packets1[i].clone()));
        extra_packets.push((j, packets2[j].clone()));
        i += 1;
        j += 1;
    }
    
    // 处理剩余包
    while i < packets1.len() {
        missing_packets.push((i, packets1[i].clone()));
        i += 1;
    }
    
    while j < packets2.len() {
        extra_packets.push((j, packets2[j].clone()));
        j += 1;
    }
    
    // 打印结果
    print_comparison_results(&packets1, &packets2, &missing_packets, &extra_packets);
    
    Ok(())
}

/// 读取PCAP文件并计算每个包的哈希值
/// 读取PCAP文件并计算每个包的哈希值
fn read_and_hash_packets(
    reader: &mut PcapReader<File>,
    ignore_timestamp: bool,
) -> Result<Vec<PacketWithHash>> {
    let mut packets = Vec::new();
    
    while let Some(packet) = reader.next() {
        let mut hasher = SeaHasher::new();
        
        if ignore_timestamp {
            // 忽略时间戳的哈希计算
            let mut buffer = Vec::new();
            buffer.extend_from_slice(&packet.header.incl_len.to_be_bytes());
            buffer.extend_from_slice(&packet.header.orig_len.to_be_bytes());
            buffer.extend_from_slice(&packet.data);
            hasher.write(&buffer);
        } else {
            // 包含完整头部和数据的哈希计算
            hasher.write(&packet.data);
        }
        
        let hash = hasher.finish();
        
        packets.push(PacketWithHash {
            original: packet,
            hash,
        });
    }
    
    Ok(packets)
}

/// 带哈希值的包结构
#[derive(Clone)]
struct PacketWithHash {
    original: pcap_file::Packet<'static>, // 使用'static生命周期
    hash: u64, // 使用64位哈希足够
}

/// 打印比较结果
fn print_comparison_results(
    pcap1: &[PacketWithHash],
    pcap2: &[PacketWithHash],
    missing: &[(usize, PacketWithHash)],
    extra: &[(usize, PacketWithHash)],
) {
    println!("PCAP内容比较结果:");
    println!("- 基准文件包数: {}", pcap1.len());
    println!("- 对比文件包数: {}", pcap2.len());
    println!("- 丢失包数: {}", missing.len());
    println!("- 多余包数: {}", extra.len());
    
    // 打印丢失包详情
    if !missing.is_empty() {
        println!("\n丢失包详情 (存在于基准文件但不在对比文件中):");
        for (idx, packet) in missing {
            let packet_size = packet.original.data.len();
            println!("  [基准包 {}] 长度: {} 字节, 哈希: {:016x}", 
                idx, packet_size, packet.hash);
        }
    }
    
    // 打印多余包详情
    if !extra.is_empty() {
        println!("\n多余包详情 (存在于对比文件但不在基准文件中):");
        for (idx, packet) in extra {
            let packet_size = packet.original.data.len();
            println!("  [对比包 {}] 长度: {} 字节, 哈希: {:016x}", 
                idx, packet_size, packet.hash);
        }
    }
    
    // 总结
    if missing.is_empty() && extra.is_empty() {
        println!("\n✅ 两个PCAP文件内容完全一致");
    } else {
        println!("\n⚠️ 发现内容差异");
    }
}