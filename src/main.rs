use rsa::{RsaPrivateKey, PaddingScheme};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::env;

fn sign_payload(payload_path: &Path, key_path: &Path) -> std::io::Result<()> {
    // 读取私钥
    let key = std::fs::read_to_string(key_path)
        .expect("Unable to read private key");
    let private_key = RsaPrivateKey::from_pem(&key)
        .expect("Unable to parse private key");

    // 读取payload
    let mut file = File::open(payload_path)?;
    let mut payload = Vec::new();
    file.read_to_end(&mut payload)?;

    // 计算SHA256哈希
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let hash = hasher.finalize();

    // 使用私钥签名哈希
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256));
    let signature = private_key.sign(padding, &hash)
        .expect("Failed to sign");

    // 将签名写入到文件
    let mut output = File::create("signature.bin")?;
    output.write_all(&signature)?;

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <payload.bin> <private.pem>", args[0]);
        return;
    }

    let payload_path = Path::new(&args[1]);
    let key_path = Path::new(&args[2]);

    if let Err(e) = sign_payload(&payload_path, &key_path) {
        eprintln!("Error: {}", e);
    }
}
