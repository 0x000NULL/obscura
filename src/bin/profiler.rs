extern crate obscura_core;

use clap::{Parser, Subcommand};
use obscura_core::utils::profiler::{set_profiling_level, ProfilingLevel, generate_report, GLOBAL_PROFILER};
use obscura_core::utils::profiler_benchmarks::{
    run_all_critical_path_benchmarks, run_high_priority_benchmarks, generate_benchmark_report
};
use std::str::FromStr;
use std::time::Duration;
use std::thread;
use log::{info, warn, error, LevelFilter};
use env_logger::Builder;
use colored::*;

#[derive(Parser)]
#[clap(author, version, about)]
/// Critical Path Profiler and Benchmarking Tool for Obscura
struct Cli {
    /// Subcommand to execute
    #[clap(subcommand)]
    command: Commands,
    
    /// Profiling verbosity level
    #[clap(short, long, default_value = "normal")]
    level: String,
    
    /// Log level for output
    #[clap(short, long, default_value = "info")]
    log_level: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all critical path benchmarks
    #[clap(alias = "bench")]
    Benchmark {
        /// Number of iterations for each benchmark
        #[clap(short, long, default_value = "100")]
        iterations: usize,
        
        /// Only run high-priority critical paths
        #[clap(short, long)]
        high_priority: bool,
        
        /// Categories to include (comma-separated)
        #[clap(short, long)]
        categories: Option<String>,
        
        /// Output file for the report
        #[clap(short, long)]
        output: Option<String>,
    },
    
    /// Run the application with profiling enabled
    #[clap(alias = "run")]
    Profile {
        /// Duration to profile in seconds
        #[clap(short, long, default_value = "60")]
        duration: u64,
        
        /// Categories to include in the report (comma-separated)
        #[clap(short, long)]
        categories: Option<String>,
        
        /// Output file for the report
        #[clap(short, long)]
        output: Option<String>,
    },
    
    /// List all registered critical paths
    #[clap(alias = "ls")]
    List {
        /// Categories to filter by (comma-separated)
        #[clap(short, long)]
        categories: Option<String>,
        
        /// Only show high-priority paths
        #[clap(short, long)]
        high_priority: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    
    // Setup logging
    let log_level = match cli.log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    
    Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();
    
    // Set profiling level
    let profiling_level = match cli.level.to_lowercase().as_str() {
        "disabled" => ProfilingLevel::Disabled,
        "minimal" => ProfilingLevel::Minimal,
        "normal" => ProfilingLevel::Normal,
        "detailed" => ProfilingLevel::Detailed,
        "debug" => ProfilingLevel::Debug,
        _ => ProfilingLevel::Normal,
    };
    
    set_profiling_level(profiling_level);
    info!("Profiling level set to {:?}", profiling_level);
    
    // Process command
    match &cli.command {
        Commands::Benchmark { iterations, high_priority, categories, output } => {
            run_benchmarks(*iterations, *high_priority, categories, output);
        },
        Commands::Profile { duration, categories, output } => {
            run_profiling(*duration, categories, output);
        },
        Commands::List { categories, high_priority } => {
            list_critical_paths(categories, *high_priority);
        }
    }
}

/// Run benchmarks on critical paths
fn run_benchmarks(
    iterations: usize, 
    high_priority: bool,
    categories: &Option<String>,
    output: &Option<String>
) {
    println!("{}", "Running Critical Path Benchmarks".green().bold());
    println!("Iterations: {}", iterations);
    println!("High Priority Only: {}", high_priority);
    
    if let Some(cats) = categories {
        println!("Categories: {}", cats);
    }
    
    println!("\nStarting benchmarks...\n");
    
    // Run appropriate benchmarks
    let results = if high_priority {
        run_high_priority_benchmarks(iterations)
    } else {
        run_all_critical_path_benchmarks(iterations)
    };
    
    // Generate and display report
    let report = generate_benchmark_report(&results);
    
    println!("\n{}", report);
    
    // Save to file if requested
    if let Some(path) = output {
        match std::fs::write(path, report) {
            Ok(_) => println!("Report saved to: {}", path),
            Err(e) => error!("Failed to write report: {}", e),
        }
    }
}

/// Run application with profiling
fn run_profiling(
    duration: u64,
    categories: &Option<String>,
    output: &Option<String>
) {
    println!("{}", "Running Application with Profiling".green().bold());
    println!("Duration: {} seconds", duration);
    
    if let Some(cats) = categories {
        println!("Categories: {}", cats);
    }
    
    println!("\nStarting application with profiling enabled...");
    println!("Press Ctrl+C to stop early and view report.");
    
    // Here you would typically start your application with profiling enabled
    // For this example, we'll just sleep for the duration
    
    // Convert duration to milliseconds for sleeping
    let sleep_duration = Duration::from_secs(duration);
    
    // Handle Ctrl+C
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, stopping profiler...");
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");
    
    // Sleep until duration or interrupt
    let start = std::time::Instant::now();
    while running.load(std::sync::atomic::Ordering::SeqCst) && start.elapsed() < sleep_duration {
        thread::sleep(Duration::from_millis(100));
    }
    
    // Generate and parse categories if specified
    let category_list = categories.as_ref().map(|cats| {
        cats.split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>()
    });
    
    // Generate report
    let report = generate_report(category_list);
    
    println!("\n{}", report);
    
    // Save to file if requested
    if let Some(path) = output {
        match std::fs::write(path, report) {
            Ok(_) => println!("Report saved to: {}", path),
            Err(e) => error!("Failed to write report: {}", e),
        }
    }
}

/// List all registered critical paths
fn list_critical_paths(
    categories: &Option<String>,
    high_priority: bool
) {
    println!("{}", "Registered Critical Paths".green().bold());
    
    // This would typically access the critical paths registry
    // For now, we'll just show a placeholder since proper integration
    // would be done after this module is fully integrated
    
    println!("\nThis functionality requires integration with the main application.");
    println!("After integrating the profiler module, this command will list all registered critical paths.");
    
    if let Some(cats) = categories {
        println!("\nFiltering by categories: {}", cats);
    }
    
    if high_priority {
        println!("Showing only high-priority paths.");
    }
} 