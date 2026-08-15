use std::process::{Command, Stdio};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// 构建 yumi-ebpf BPF 程序，参照 frame-analyzer 的 build_ebpf()
fn build_ebpf() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_dir = manifest_dir.join("yumi-ebpf");
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let target_dir = out_dir.join("ebpf_target");
    let tools_dir = out_dir.join("ebpf_tools");
    let tools_bin = tools_dir.join("bin");

    // 监控 ebpf crate 变化
    println!("cargo:rerun-if-changed={}", ebpf_dir.join("Cargo.toml").display());
    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());

    // 1. 确保 bpf-linker 可用（PATH 上已有则直接复用，否则下载官方预编译二进制）
    ensure_bpf_linker(&tools_bin)?;

    // 2. 编译 BPF 程序（在 yumi-ebpf 目录中，避免 workspace 干扰）
    let mut ebpf_args = vec![
        "--target", "bpfel-unknown-none",
        "-Z", "build-std=core",
        "--target-dir", target_dir.to_str().unwrap(),
    ];

    #[cfg(not(debug_assertions))]
    ebpf_args.push("--release");

    let status = Command::new("cargo")
        .arg("build")
        .args(&ebpf_args)
        .current_dir(&ebpf_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("PATH", add_path(&tools_bin)?)
        .status()?;

    if !status.success() {
        panic!("yumi-ebpf 编译失败");
    }

    // 3. 产物路径（binary crate 直接输出到 <target>/<profile>/<name>，无 deps/hash）
    #[cfg(debug_assertions)]
    let profile = "debug";
    #[cfg(not(debug_assertions))]
    let profile = "release";

    let built_obj = target_dir
        .join("bpfel-unknown-none")
        .join(profile)
        .join("yumi-ebpf"); // binary crate 保留原始包名中的连字符

    Ok(built_obj)
}

fn add_path(add: &std::path::Path) -> Result<String, std::env::VarError> {
    let path = env::var("PATH")?;
    Ok(format!("{}:{}", add.display(), path))
}

/// 检查 PATH 上是否已存在可用的 bpf-linker
fn bpf_linker_available() -> bool {
    Command::new("bpf-linker")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// bpf-linker 依赖特定版本的 LLVM，`cargo install` 在无 LLVM 的环境（如 CI）下无法编译。
/// 这里直接下载官方发布的预编译静态二进制（已内嵌 LLVM），无需系统 LLVM。
fn ensure_bpf_linker(tools_bin: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if bpf_linker_available() {
        return Ok(());
    }

    fs::create_dir_all(tools_bin)?;
    let host = env::var("HOST").unwrap_or_else(|_| "x86_64-unknown-linux-gnu".to_string());
    let asset = if host.starts_with("aarch64-unknown-linux") {
        "bpf-linker-aarch64-unknown-linux-musl.tar.zst"
    } else {
        "bpf-linker-x86_64-unknown-linux-musl.tar.zst"
    };
    let url = format!("https://github.com/aya-rs/bpf-linker/releases/latest/download/{asset}");
    let tarball = tools_bin.join(asset);

    let status = Command::new("curl")
        .args(["-L", "-f", "-o", tarball.to_str().unwrap(), &url])
        .status()?;
    if !status.success() {
        return Err(format!("下载 bpf-linker 失败: {url}").into());
    }

    let status = Command::new("tar")
        .args(["-xpf", tarball.to_str().unwrap(), "-C", tools_bin.to_str().unwrap()])
        .status()?;
    if !status.success() {
        return Err(format!("解压 bpf-linker 失败: {}", tarball.display()).into());
    }

    let _ = fs::remove_file(&tarball);

    if !tools_bin.join("bpf-linker").exists() {
        return Err("bpf-linker 安装后仍不可用".into());
    }
    Ok(())
}

fn main() {
    match build_ebpf() {
        Ok(bpf_obj) => {
            println!("cargo:warning=✅ yumi-ebpf 编译成功: {}", bpf_obj.display());
        }
        Err(e) => {
            panic!("yumi-ebpf 编译失败: {e}");
        }
    }
}
