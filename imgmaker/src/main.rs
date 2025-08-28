use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha1::{Digest, Sha1};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;

// Constants
const BUFSIZ: usize = 8192;
const SHA_DIGEST_LENGTH: usize = 20;

#[repr(C)]
#[derive(Debug, Clone)]
struct AkaiImageHeader {
    header: [u8; 4],      // AZ01
    value1: u32,          // 01 00 00 00 (little endian)
    value2: u32,          // 74 00 00 00 (Force) or 08 01 00 00
    img_name_len: u32,    // including 0 terminated
    img_name: [u8; 24],   // At this stage, it is a hard coded size. Null terminated.
}

#[repr(C)]
#[derive(Debug, Clone)]
struct CompatTable {
    device_name_len: u32,
    device_name: [u8; 16],
    usb_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
struct PartInfo {
    tag: [u8; 8],         // "PARTL" + padding
    size: u64,            // Partition len
    part_type: u32,       // Partition type
    name: [u8; 8],        // Partition name
    format: u32,          // Partition format
    comp_type: [u8; 4],   // Compression type
    info1: u32,
    info2: u32,
    hash_algo: [u8; 8],   // Hashcode algo
    hash_len: u32,        // Hash len
    hash_code: [u8; 20],  // Hashcode
}

#[derive(Debug)]
struct AkaiImage {
    h: AkaiImageHeader,
    device_count: u32,
    dev: Vec<CompatTable>,
    img_desc_len: u32,
    img_desc: Vec<u8>,
    p: PartInfo,
    partl_offset: u64,    // PARTL tag offset
    xz_part_offset: u64,  // xz Offset from the beginning of the image
}

impl AkaiImageHeader {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        let value1 = reader.read_u32::<LittleEndian>()?;
        let value2 = reader.read_u32::<LittleEndian>()?;
        let img_name_len = reader.read_u32::<LittleEndian>()?;
        let mut img_name = [0u8; 24];
        reader.read_exact(&mut img_name)?;

        Ok(AkaiImageHeader {
            header,
            value1,
            value2,
            img_name_len,
            img_name,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.header)?;
        writer.write_u32::<LittleEndian>(self.value1)?;
        writer.write_u32::<LittleEndian>(self.value2)?;
        writer.write_u32::<LittleEndian>(self.img_name_len)?;
        writer.write_all(&self.img_name)?;
        Ok(())
    }
}

impl CompatTable {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let device_name_len = reader.read_u32::<LittleEndian>()?;
        let mut device_name = [0u8; 16];
        reader.read_exact(&mut device_name)?;
        let usb_id = reader.read_u32::<LittleEndian>()?;

        Ok(CompatTable {
            device_name_len,
            device_name,
            usb_id,
        })
    }
}

impl PartInfo {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut tag = [0u8; 8];
        reader.read_exact(&mut tag)?;
        let size = reader.read_u64::<LittleEndian>()?;
        let part_type = reader.read_u32::<LittleEndian>()?;
        let mut name = [0u8; 8];
        reader.read_exact(&mut name)?;
        let format = reader.read_u32::<LittleEndian>()?;
        let mut comp_type = [0u8; 4];
        reader.read_exact(&mut comp_type)?;
        let info1 = reader.read_u32::<LittleEndian>()?;
        let info2 = reader.read_u32::<LittleEndian>()?;
        let mut hash_algo = [0u8; 8];
        reader.read_exact(&mut hash_algo)?;
        let hash_len = reader.read_u32::<LittleEndian>()?;
        let mut hash_code = [0u8; 20];
        reader.read_exact(&mut hash_code)?;

        Ok(PartInfo {
            tag,
            size,
            part_type,
            name,
            format,
            comp_type,
            info1,
            info2,
            hash_algo,
            hash_len,
            hash_code,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.tag)?;
        writer.write_u64::<LittleEndian>(self.size)?;
        writer.write_u32::<LittleEndian>(self.part_type)?;
        writer.write_all(&self.name)?;
        writer.write_u32::<LittleEndian>(self.format)?;
        writer.write_all(&self.comp_type)?;
        writer.write_u32::<LittleEndian>(self.info1)?;
        writer.write_u32::<LittleEndian>(self.info2)?;
        writer.write_all(&self.hash_algo)?;
        writer.write_u32::<LittleEndian>(self.hash_len)?;
        writer.write_all(&self.hash_code)?;
        Ok(())
    }
}

fn compute_sha1(file_path: &Path) -> Result<[u8; SHA_DIGEST_LENGTH]> {
    let mut file = File::open(file_path)?;
    let mut hasher = Sha1::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; SHA_DIGEST_LENGTH];
    hash.copy_from_slice(&result);
    
    print!("SHA-1 of {}: ", file_path.display());
    for byte in &hash {
        print!("{:02x} ", byte);
    }
    println!();

    Ok(hash)
}

fn decompress_xz(input_path: &Path, output_path: &Path) -> Result<()> {
    let input_file = File::open(input_path)?;
    let mut decoder = XzDecoder::new(BufReader::new(input_file));
    let output_file = File::create(output_path)?;
    let mut writer = BufWriter::new(output_file);

    io::copy(&mut decoder, &mut writer)?;
    writer.flush()?;
    Ok(())
}

fn compress_xz(input_path: &Path, output_path: &Path) -> Result<u64> {
    let input_file = File::open(input_path)?;
    let mut reader = BufReader::new(input_file);
    let output_file = File::create(output_path)?;
    let encoder = XzEncoder::new(BufWriter::new(output_file), 6);
    let mut writer = BufWriter::new(encoder);

    // Get input file size for progress reporting
    let input_size = std::fs::metadata(input_path)?.len();
    let mut bytes_read = 0u64;
    let mut buffer = [0u8; BUFSIZ];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buffer[..n])?;
        bytes_read += n as u64;

        // Progress reporting every 10MB
        if bytes_read % (1024 * 1024 * 10) == 0 {
            print!(" -> {} / {} bytes read     \r", bytes_read, input_size);
            io::stdout().flush()?;
        }
    }

    println!(" -> {} bytes read (EOF).                          ", bytes_read);
    writer.flush()?;
    
    // Get compressed file size
    let compressed_size = std::fs::metadata(output_path)?.len();
    Ok(compressed_size)
}

fn display_akai_image_info(filename: &Path, extract_temp: bool) -> Result<AkaiImage> {
    let mut file = File::open(filename)?;
    
    // Read header
    let header = AkaiImageHeader::read_from(&mut file)?;
    
    // Check if it is the right header
    if &header.header != b"AZ01" {
        return Err(anyhow!("Invalid header: AZ01 string not found ({:?})", std::str::from_utf8(&header.header).unwrap_or("invalid utf8")));
    }

    // Extract null-terminated string from img_name
    let img_name_str = std::str::from_utf8(&header.img_name)
        .unwrap_or("invalid utf8")
        .trim_end_matches('\0');
    println!("Image Name            : {}", img_name_str);

    // Read compatible devices
    let device_count = file.read_u32::<LittleEndian>()?;
    print!("{} compatible devices  : ", device_count);
    
    let mut devices = Vec::new();
    for _ in 0..device_count {
        let device_name_len = file.read_u32::<LittleEndian>()?;
        let mut device_name = [0u8; 16];
        file.read_exact(&mut device_name)?;
        
        let device_name_str = std::str::from_utf8(&device_name[..device_name_len as usize])
            .unwrap_or("invalid utf8");
        print!("{}, ", device_name_str);
        
        devices.push(CompatTable {
            device_name_len,
            device_name,
            usb_id: 0, // Will be filled later
        });
    }
    println!();
    print!("                      : ");

    // Read USB IDs
    let usb_device_count = file.read_u32::<LittleEndian>()?;
    for i in 0..usb_device_count {
        let usb_id = file.read_u32::<LittleEndian>()?;
        print!("0x{:08x}, ", usb_id);
        if (i as usize) < devices.len() {
            devices[i as usize].usb_id = usb_id;
        }
    }
    println!();

    // Read image description
    let img_desc_len = file.read_u32::<LittleEndian>()?;
    let mut img_desc = vec![0u8; img_desc_len as usize];
    file.read_exact(&mut img_desc)?;

    // Find PARTL tag by skipping padding
    let mut pad = [0u8; 1];
    loop {
        file.read_exact(&mut pad)?;
        if pad[0] == b'P' {
            break;
        }
    }
    file.seek(SeekFrom::Current(-1))?;

    // Read partition info
    println!("Partition Information:");
    let partl_offset = file.stream_position()?;
    
    let part_info = PartInfo::read_from(&mut file)?;
    
    if &part_info.tag[..5] != b"PARTL" {
        return Err(anyhow!("'PARTL' rootfs partition tag not found"));
    }

    println!("  Compressed Size     : {} bytes", part_info.size);
    
    let part_name_str = std::str::from_utf8(&part_info.name)
        .unwrap_or("invalid utf8")
        .trim_end_matches('\0');
    println!("  Partition Name      : {}", part_name_str);
    
    let comp_type_str = std::str::from_utf8(&part_info.comp_type)
        .unwrap_or("invalid utf8")
        .trim_end_matches('\0');
    println!("  Compression Type    : {}", comp_type_str);
    
    let hash_algo_str = std::str::from_utf8(&part_info.hash_algo)
        .unwrap_or("invalid utf8")
        .trim_end_matches('\0');
    print!("  Hash Code ({})    : ", hash_algo_str);
    
    for i in 0..part_info.hash_len {
        print!("{:02x} ", part_info.hash_code[i as usize]);
    }
    println!();

    let xz_part_offset = file.stream_position()?;
    println!("  XZ Part. offset     : {} (0x{:x})", xz_part_offset, xz_part_offset);

    // Extract compressed partition if needed
    if extract_temp {
        let temp_filename = format!("{}.tmp.xz", filename.display());
        let temp_path = Path::new(&temp_filename);
        
        let mut temp_file = File::create(temp_path)?;
        let mut remaining = part_info.size;
        let mut buffer = [0u8; 4096];
        
        while remaining > 0 {
            let to_read = std::cmp::min(buffer.len() as u64, remaining) as usize;
            file.read_exact(&mut buffer[..to_read])?;
            temp_file.write_all(&buffer[..to_read])?;
            remaining -= to_read as u64;
        }
        
        temp_file.flush()?;
    } else {
        file.seek(SeekFrom::Current(part_info.size as i64))?;
    }

    // Check EOF tag with 8-byte alignment
    let current_pos = file.stream_position()?;
    let seek_amount = (8 - (current_pos % 8)) % 8;
    if seek_amount > 0 {
        file.seek(SeekFrom::Current(seek_amount as i64))?;
    }

    let mut eof_marker = [0u8; 3];
    file.read_exact(&mut eof_marker)?;
    if &eof_marker != b"EOF" {
        println!("'EOF' tag not found. Image file is probably corrupted.");
    }

    println!();

    Ok(AkaiImage {
        h: header,
        device_count,
        dev: devices,
        img_desc_len,
        img_desc,
        p: part_info,
        partl_offset,
        xz_part_offset,
    })
}

fn extract_rootfs_partition(in_img_filename: &Path, out_part_filename: &Path) -> Result<()> {
    let temp_filename = format!("{}.tmp.xz", in_img_filename.display());
    let temp_path = Path::new(&temp_filename);
    
    // Remove existing temp file
    let _ = std::fs::remove_file(temp_path);

    // Populate Akai image info struct and extract temp file
    let _akai_img = display_akai_image_info(in_img_filename, true)?;

    // Compute hash and verify
    let _computed_hash = compute_sha1(temp_path)?;
    
    println!("Extracting {} from Akai image file...", out_part_filename.display());
    decompress_xz(temp_path, out_part_filename)?;
    
    // Clean up temp file
    let _ = std::fs::remove_file(temp_path);
    
    println!("Done.");
    Ok(())
}

fn make_akai_image(in_img_filename: &Path, in_part_filename: &Path, out_img_filename: &Path) -> Result<()> {
    // Populate Akai image info struct
    let mut akai_img = display_akai_image_info(in_img_filename, false)?;

    let out_img_file = File::create(out_img_filename)?;
    let mut out_img_writer = BufWriter::new(out_img_file);

    let mut in_img_file = File::open(in_img_filename)?;
    
    // Create temp compressed file
    let temp_filename = format!("{}.tmp.xz", in_part_filename.display());
    let temp_path = Path::new(&temp_filename);
    let _ = std::fs::remove_file(temp_path);

    println!("Lzma (xz) encoding file {}. Please wait...", in_part_filename.display());
    let compressed_size = compress_xz(in_part_filename, temp_path)?;
    
    // Update partition size
    akai_img.p.size = compressed_size;
    
    println!("Size of compressed new rootfs partition is {} bytes", compressed_size);

    // Compute SHA-1 of compressed file
    let hash = compute_sha1(temp_path)?;
    akai_img.p.hash_code = hash;

    println!("Writing new Akai image {}. Please wait...", out_img_filename.display());

    // Copy input image until PARTL position
    let mut buffer = vec![0u8; akai_img.partl_offset as usize];
    in_img_file.read_exact(&mut buffer)?;
    out_img_writer.write_all(&buffer)?;

    // Write the new partition info
    akai_img.p.write_to(&mut out_img_writer)?;

    // Write the compressed partition file
    let mut temp_file = File::open(temp_path)?;
    let mut remaining = compressed_size;
    let mut copy_buffer = [0u8; 512];
    
    while remaining > 0 {
        let to_read = std::cmp::min(copy_buffer.len() as u64, remaining) as usize;
        temp_file.read_exact(&mut copy_buffer[..to_read])?;
        out_img_writer.write_all(&mut copy_buffer[..to_read])?;
        remaining -= to_read as u64;
    }

    // Clean up temp file
    let _ = std::fs::remove_file(temp_path);

    // Write EOF padding and marker
    let current_pos = out_img_writer.stream_position()?;
    let padding_needed = (8 - (current_pos % 8)) % 8;
    if padding_needed > 0 {
        let zero_pad = vec![0u8; padding_needed as usize];
        out_img_writer.write_all(&zero_pad)?;
    }

    // Copy last 16 bytes from input image (EOF section)
    in_img_file.seek(SeekFrom::End(-16))?;
    let mut eof_bytes = [0u8; 16];
    in_img_file.read_exact(&mut eof_bytes)?;
    out_img_writer.write_all(&eof_bytes)?;

    out_img_writer.flush()?;

    println!("All operations done. New Akai image {} ready.\n", out_img_filename.display());
    Ok(())
}

fn print_help() {
    println!("Usage : mpcimg2 <action> <FILE>...");
    println!("Actions are : ");
    println!(" -i <Akai image V2 file in>");
    println!("    : Display various information about the Akai image\n");
    println!(" -x <Akai image V2 file in>");
    println!("    : Extraction of the embedded XZ partition file.");
    println!("    : Will generate a <your file name>.tmp.xz file in the current directory\n");
    println!(" -r <Akai image V2 file in> <rootfs file out>");
    println!("    : Uncompress the rootfs partition embedded within the Akai image");
    println!("    : The <rootfs file out> extracted is ready to mount on any Linux file system\n");
    println!(" -m <Akai image V2 file in> <rootfs file in> <Akai img V2 file out>");
    println!("    : Make a new image by providing your own rootfs partition");
    println!("    : The modified rootfs parttion size must be exactly the same as the original one\n");
}

fn main() -> Result<()> {
    println!("\nAKAI MPC IMAGE TOOL - V2 - NEW MPC IMG FORMAT (FROM V3.4)");
    println!("https://github.com/TheKikGen/MPC-LiveXplore");
    println!("(c) The KikGen labs.\n");

    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_help();
        std::process::exit(1);
    }

    let action = &args[1];

    match action.as_str() {
        "-i" => {
            if args.len() != 3 {
                print_help();
                std::process::exit(1);
            }
            display_akai_image_info(Path::new(&args[2]), false)?;
        }
        "-x" => {
            if args.len() != 3 {
                print_help();
                std::process::exit(1);
            }
            display_akai_image_info(Path::new(&args[2]), true)?;
        }
        "-r" => {
            if args.len() != 4 {
                print_help();
                std::process::exit(1);
            }
            extract_rootfs_partition(Path::new(&args[2]), Path::new(&args[3]))?;
        }
        "-m" => {
            if args.len() != 5 {
                print_help();
                std::process::exit(1);
            }
            make_akai_image(Path::new(&args[2]), Path::new(&args[3]), Path::new(&args[4]))?;
        }
        _ => {
            print_help();
            std::process::exit(1);
        }
    }

    Ok(())
}