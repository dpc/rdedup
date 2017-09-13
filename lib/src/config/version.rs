
use asyncio;
use SGData;
use std::io;
use std::path::PathBuf;
use std::io::Write;

pub const REPO_VERSION_LOWEST: u32 = 2;
pub const REPO_VERSION_CURRENT: u32 = 2;
pub const VERSION_FILE: &'static str = "version";

pub(crate) struct VersionFile(u32);

impl VersionFile {
    pub(crate) fn current() -> VersionFile {
        VersionFile(REPO_VERSION_CURRENT)
    }
    pub(crate) fn write(&self, aio: &asyncio::AsyncIO) -> io::Result<()> {
        let mut v = Vec::with_capacity(4 * 1024);
        {
            write!(&mut v, "{}", self.0)?;
        }

        aio.write(VERSION_FILE.into(), SGData::from_single(v))
            .wait()?;
        Ok(())
    }

    #[allow(unknown_lints)]
    #[allow(absurd_extreme_comparisons)]
    pub(crate) fn read(aio: &asyncio::AsyncIO) -> io::Result<VersionFile> {
        let version = aio.read(PathBuf::from(VERSION_FILE))
            .wait()?
            .to_linear_vec();
        let version = String::from_utf8_lossy(&version);

        let version_int = version.parse::<u32>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "can't parse version file; \
                     unsupported repo format version: {}",
                    version
                ),
            )
        })?;

        if version_int > REPO_VERSION_CURRENT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "repo version {} higher than \
                     supported {}; update?",
                    version,
                    REPO_VERSION_CURRENT
                ),
            ));
        }
        // This if statement triggers the absurd_extreme_comparisons because the
        // minimum repo version is also the smallest value of a u32
        if version_int < REPO_VERSION_LOWEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "repo version {} lower than \
                     lowest supported {}; \
                     restore using older version?",
                    version,
                    REPO_VERSION_LOWEST
                ),
            ));
        }

        Ok(VersionFile(version_int))
    }
}
