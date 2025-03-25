pub mod profiler;
pub mod profiler_benchmarks;
pub mod profiler_viz;
pub mod time;

// Re-export time utilities
pub use time::{current_time, is_timestamp_valid, time_since, format_time_diff};

// Re-export profiler utilities
pub use profiler::{
    profile, profile_with_level, set_profiling_level, 
    get_profiling_level, generate_report, reset_profiling_stats, 
    ProfilingLevel, GLOBAL_PROFILER
};

// Re-export visualization utilities
pub use profiler_viz::{
    generate_visualization, print_colored_report, 
    generate_full_visualization, OutputFormat
}; 