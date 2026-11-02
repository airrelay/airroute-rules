use std::{fs, path::Path};
fn inspect(path: &Path) -> usize {
    let mut n = 0;
    for entry in fs::read_dir(path).expect("read console assets") {
        let entry = entry.expect("console entry");
        let ty = entry.file_type().expect("asset type");
        assert!(
            !ty.is_symlink(),
            "symlinks are not permitted in embedded assets"
        );
        if ty.is_dir() {
            n += inspect(&entry.path());
        } else {
            assert!(
                entry.path().extension().is_none_or(|e| e != "map"),
                "source maps must not be shipped"
            );
            n += 1;
        }
    }
    n
}
fn main() {
    println!("cargo:rerun-if-changed=web/console/dist");
    let dist = Path::new("web/console/dist");
    let html=fs::read_to_string(dist.join("index.html")).expect("Build the embedded console first: npm --prefix web/console ci && npm --prefix web/console run build");
    for prefix in ["src=\"/assets/", "href=\"/assets/"] {
        for part in html.split(prefix).skip(1) {
            let name = part.split('"').next().expect("asset filename");
            assert!(
                !name.contains("..") && dist.join("assets").join(name).is_file(),
                "missing console asset: {name}"
            );
        }
    }
    assert!(inspect(dist) >= 3, "incomplete embedded console");
}
