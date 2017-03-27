use slog::Logger;
use std::time;


pub fn measure<F, R>(time: &mut time::Duration, f: F) -> R
    where F: FnOnce() -> R
{
    let start = time::Instant::now();

    let r = f();

    let end = time::Instant::now();

    *time += end - start;

    r
}

pub struct PipelinePerf {
    input_time: time::Duration,
    output_time: time::Duration,
    inside_time: time::Duration,
    name: String,
    log: Logger,
}

impl PipelinePerf {
    pub fn new<S: Into<String>>(name: S, log: Logger) -> Self {
        PipelinePerf {
            input_time: time::Duration::new(0, 0),
            inside_time: time::Duration::new(0, 0),
            output_time: time::Duration::new(0, 0),
            name: name.into(),
            log: log,
        }
    }

    pub fn input<F, R>(&mut self, f: F) -> R
        where F: FnOnce() -> R
    {
        measure(&mut self.input_time, f)
    }

    pub fn inside<F, R>(&mut self, f: F) -> R
        where F: FnOnce() -> R
    {
        measure(&mut self.inside_time, f)
    }

    pub fn output<F, R>(&mut self, f: F) -> R
        where F: FnOnce() -> R
    {
        measure(&mut self.output_time, f)
    }
}

impl Drop for PipelinePerf {
    fn drop(&mut self) {
        debug!(self.log, "total time";
               "name" => &self.name,
               "input" =>
               self.input_time.as_secs() as f64
               + self.input_time.subsec_nanos() as f64 / 1000000000f64,
               "inside" =>
               self.inside_time.as_secs() as f64
               + self.inside_time.subsec_nanos() as f64 / 1000000000f64,
               "output" =>
               self.output_time.as_secs() as f64
               + self.output_time.subsec_nanos() as f64 / 1000000000f64,
               )

    }
}
