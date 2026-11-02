//! A prepared commit is durable. Recovery never rebases old output onto a new head.
use anyhow::{Context, Result, ensure};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) struct Git<'a> {
    pub path: PathBuf,
    askpass: PathBuf,
    remote: &'a str,
    branch: &'a str,
    token: Option<&'a str>,
    #[cfg(test)]
    executable: PathBuf,
    #[cfg(test)]
    timeout: Duration,
}
pub(super) enum Remote {
    Published(String),
    Base,
    Conflict(String),
}
impl<'a> Git<'a> {
    pub fn new(
        path: PathBuf,
        remote: &'a str,
        branch: &'a str,
        token: Option<&'a str>,
    ) -> Result<Self> {
        std::fs::create_dir_all(&path)?;
        let askpass = path.join("askpass");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
            std::fs::write(
                &askpass,
                "#!/bin/sh\ncase \"$1\" in *sername*) printf '%s\\n' x-access-token ;; *) printf '%s\\n' \"$AIRROUTE_GIT_TOKEN\" ;; esac\n",
            )?;
            std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            path,
            askpass,
            remote,
            branch,
            token,
            #[cfg(test)]
            executable: "git".into(),
            #[cfg(test)]
            timeout: Duration::from_secs(180),
        })
    }
    async fn run(&self, args: &[&str]) -> Result<std::process::Output> {
        #[cfg(test)]
        let mut command = tokio::process::Command::new(&self.executable);
        #[cfg(not(test))]
        let mut command = tokio::process::Command::new("git");
        command
            .current_dir(&self.path)
            .args(["-c", "credential.helper=", "-c", "core.hooksPath=/dev/null"])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", &self.askpass)
            .env("AIRROUTE_GIT_TOKEN", self.token.unwrap_or(""))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .kill_on_drop(true);
        #[cfg(test)]
        let timeout = self.timeout;
        #[cfg(not(test))]
        let timeout = Duration::from_secs(180);
        Ok(tokio::time::timeout(timeout, command.output())
            .await
            .context("git operation timed out")??)
    }
    fn checked(&self, output: std::process::Output) -> Result<String> {
        ensure!(
            output.status.success(),
            "git operation failed: {}",
            self.redact(&String::from_utf8_lossy(&output.stderr))
        );
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
    fn redact(&self, error: &str) -> String {
        error
            .replace(
                self.token.filter(|s| !s.is_empty()).unwrap_or("\0"),
                "[redacted]",
            )
            .chars()
            .take(1200)
            .collect()
    }
    async fn command(&self, args: &[&str]) -> Result<String> {
        self.checked(self.run(args).await?)
    }
    fn reference(&self) -> String {
        format!("refs/heads/{}", self.branch)
    }
    pub async fn head(&self) -> Result<String> {
        let heads = self
            .command(&["ls-remote", "--heads", self.remote, &self.reference()])
            .await?;
        Ok(heads.split_whitespace().next().unwrap_or("").to_owned())
    }
    pub async fn prepare(&self, output: &Path, release: &str) -> Result<(String, String)> {
        self.command(&["init", "--quiet"]).await?;
        let head = self.head().await?;
        let base = if head.is_empty() {
            self.command(&["checkout", "--orphan", self.branch]).await?;
            String::new()
        } else {
            self.command(&["fetch", "--depth=1", self.remote, &self.reference()])
                .await?;
            self.command(&["checkout", "-B", self.branch, "FETCH_HEAD"])
                .await?;
            self.command(&["rev-parse", "HEAD"]).await?
        };
        for kind in ["region", "category", "provider", "special"] {
            let dest = self.path.join(kind);
            remove_entry(&dest)?;
            std::fs::create_dir(&dest)?;
            for entry in std::fs::read_dir(output.join(kind))? {
                let entry = entry?;
                ensure!(
                    entry.file_type()?.is_file()
                        && entry.path().extension().is_some_and(|e| e == "list"),
                    "unexpected export file"
                );
                std::fs::copy(entry.path(), dest.join(entry.file_name()))?;
            }
        }
        let readme = self.path.join("README.md");
        remove_entry(&readme)?;
        std::fs::copy(output.join("README.md"), readme)?;
        // The IP library is a managed public artifact. Legacy releases may
        // predate it; prepared historical commits keep their original SHA.
        let library = self.path.join("ip-library.csv");
        let had_library = library.symlink_metadata().is_ok();
        remove_entry(&library)?;
        let source_library = output.join("ip-library.csv");
        let has_library = source_library.symlink_metadata().is_ok();
        if has_library {
            ensure!(
                source_library.symlink_metadata()?.file_type().is_file(),
                "invalid IP library artifact"
            );
            std::fs::copy(source_library, library)?;
        }
        let mut paths = vec![
            "add",
            "--",
            "region",
            "category",
            "provider",
            "special",
            "README.md",
        ];
        if had_library || has_library {
            paths.push("ip-library.csv");
        }
        self.command(&paths).await?;
        let changed = self.run(&["diff", "--cached", "--quiet"]).await?;
        ensure!(
            changed.status.code().is_some_and(|c| c <= 1),
            "git diff failed"
        );
        if !changed.status.success() {
            self.command(&[
                "-c",
                "user.name=AirRoute Rules",
                "-c",
                "user.email=rules@users.noreply.github.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                &format!("rules: {release}"),
            ])
            .await?;
        }
        let sha = self.command(&["rev-parse", "HEAD"]).await?;
        Ok((base, sha))
    }
    pub async fn reconcile(&self, sha: &str, base: &str) -> Result<Remote> {
        // The directory may have been lost, but the server can still contain the persisted SHA.
        self.command(&["init", "--quiet"]).await?;
        let actual = self.head().await?;
        if actual == sha {
            return Ok(Remote::Published(actual));
        }
        if actual == base {
            return Ok(Remote::Base);
        }
        if !actual.is_empty() {
            // Reconciliation is bounded and normally needs only a few commits.
            // If ancestry cannot be proven in this window, retain uncertainty;
            // do not clone the entire daily rule history or invent a new commit.
            self.command(&[
                "fetch",
                "--filter=blob:none",
                "--depth=64",
                self.remote,
                &self.reference(),
            ])
            .await?;
            let fetched = self.command(&["rev-parse", "FETCH_HEAD"]).await?;
            let ancestor = self
                .run(&["merge-base", "--is-ancestor", sha, &fetched])
                .await?;
            if ancestor.status.success() {
                return Ok(Remote::Published(fetched));
            }
        }
        Ok(Remote::Conflict(actual))
    }
    pub async fn push(&self, sha: &str) -> Result<()> {
        // Use the persisted commit, never the incidental current HEAD or a forced update.
        self.command(&["push", self.remote, &format!("{sha}:{}", self.reference())])
            .await?;
        Ok(())
    }
}
fn remove_entry(path: &Path) -> Result<()> {
    if let Ok(metadata) = path.symlink_metadata() {
        if metadata.is_dir() && !metadata.is_symlink() {
            std::fs::remove_dir_all(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[tokio::test]
    async fn real_push_with_lost_response_is_reconciled_without_another_push() {
        let d = tempfile::tempdir().unwrap();
        let remote = d.path().join("remote.git");
        let initialized = std::process::Command::new("git")
            .args(["init", "--bare"])
            .arg(&remote)
            .output()
            .unwrap();
        assert!(initialized.status.success());
        let output = d.path().join("output");
        for kind in ["region", "category", "provider", "special"] {
            std::fs::create_dir_all(output.join(kind)).unwrap();
            std::fs::write(output.join(kind).join("a.list"), "DOMAIN,example.com\n").unwrap();
        }
        std::fs::write(output.join("README.md"), "rules\n").unwrap();
        std::fs::write(
            output.join("ip-library.csv"),
            "family,start,end,region,anycast\n4,1.1.1.1,1.1.1.1,us,false\n",
        )
        .unwrap();
        let mut git = Git::new(
            d.path().join("checkout"),
            remote.to_str().unwrap(),
            "main",
            None,
        )
        .unwrap();
        let (base, sha) = git.prepare(&output, "abc").await.unwrap();
        let executable = std::process::Command::new("which")
            .arg("git")
            .output()
            .unwrap();
        assert!(executable.status.success());
        let executable = String::from_utf8(executable.stdout).unwrap();
        let executable = executable.trim().replace('\'', "'\\''");
        let wrapper = d.path().join("git-delayed-response");
        // Actual git completes the remote mutation. Delay only its acknowledgement,
        // never the fetch/ls-remote used to independently check the remote state.
        std::fs::write(&wrapper,format!("#!/bin/sh\ncase \" $* \" in *' push '*) '{executable}' \"$@\" || exit $?; exec sleep 10 ;; *) exec '{executable}' \"$@\" ;; esac\n")).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        git.executable = wrapper;
        git.timeout = Duration::from_secs(2);
        assert!(
            git.push(&sha)
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert!(
            matches!(git.reconcile(&sha,&base).await.unwrap(), Remote::Published(actual) if actual==sha)
        );
        let count = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(&remote)
            .args(["rev-list", "--count", "refs/heads/main"])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&count.stdout).trim(), "1");
    }
}
