//! Profiler visualization tools
//!
//! This module provides visualization tools for profiler data to help
//! identify and analyze critical paths in the system.

use std::collections::HashMap;
use std::time::Duration;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use super::profiler::{GLOBAL_PROFILER, ProfileStats};
use colored::*;

/// Format for visualization output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Text-based visualization
    Text,
    /// HTML format for browser viewing
    Html,
    /// JSON format for external tools
    Json,
    /// CSV format for spreadsheet software
    Csv,
    /// Flame graph input format
    FlameGraph,
}

/// Generate a visualization of profiling data
pub fn generate_visualization(
    format: OutputFormat,
    categories: Option<Vec<String>>,
    output_path: Option<&str>,
) -> io::Result<String> {
    // Get all stats from the global profiler
    let stats = GLOBAL_PROFILER.get_all_stats();
    
    // Filter by categories if specified
    let filtered_stats = if let Some(ref cats) = categories {
        stats.into_iter()
            .filter(|s| cats.contains(&s.category))
            .collect::<Vec<_>>()
    } else {
        stats
    };
    
    // Generate the appropriate format
    let output = match format {
        OutputFormat::Text => generate_text_visualization(&filtered_stats),
        OutputFormat::Html => generate_html_visualization(&filtered_stats),
        OutputFormat::Json => generate_json_visualization(&filtered_stats)?,
        OutputFormat::Csv => generate_csv_visualization(&filtered_stats),
        OutputFormat::FlameGraph => generate_flamegraph_visualization(&filtered_stats),
    };
    
    // Write to file if specified
    if let Some(path) = output_path {
        let mut file = File::create(path)?;
        file.write_all(output.as_bytes())?;
    }
    
    Ok(output)
}

/// Generate a simple text-based visualization
fn generate_text_visualization(stats: &[ProfileStats]) -> String {
    let mut output = String::new();
    
    output.push_str("Critical Path Visualization\n");
    output.push_str("===========================\n\n");
    
    // Group by category
    let mut by_category: HashMap<String, Vec<&ProfileStats>> = HashMap::new();
    for stat in stats {
        by_category.entry(stat.category.clone())
            .or_default()
            .push(stat);
    }
    
    // Calculate the total time across all operations
    let total_time: Duration = stats.iter()
        .map(|s| s.total_time)
        .sum();
    
    output.push_str(&format!("Total profiled time: {:?}\n\n", total_time));
    
    // Generate visualization for each category
    for (category, cat_stats) in by_category.iter() {
        output.push_str(&format!("Category: {}\n", category));
        output.push_str(&format!("{}\n", "=".repeat(category.len() + 9)));
        
        // Sort by total time spent (descending)
        let mut sorted_stats = cat_stats.clone();
        sorted_stats.sort_by(|a, b| b.total_time.cmp(&a.total_time));
        
        // Find the longest operation name for alignment
        let max_name_len = sorted_stats.iter()
            .map(|s| s.name.len())
            .max()
            .unwrap_or(10);
        
        // Print each operation with a bar representing its percentage of time
        for stat in sorted_stats {
            let percentage = if total_time.as_nanos() > 0 {
                (stat.total_time.as_nanos() as f64 / total_time.as_nanos() as f64) * 100.0
            } else {
                0.0
            };
            
            let bar_length = (percentage as usize).min(50);
            let bar = "#".repeat(bar_length);
            
            output.push_str(&format!(
                "{:<width$} | {:>6.2}% | {:?} | {} calls | {}\n",
                stat.name,
                percentage,
                stat.average_time(),
                stat.call_count,
                bar,
                width = max_name_len
            ));
        }
        
        output.push_str("\n");
    }
    
    output
}

/// Generate an HTML visualization
fn generate_html_visualization(stats: &[ProfileStats]) -> String {
    let mut output = String::new();
    
    // HTML header
    output.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Obscura Critical Path Profiling</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        .category { margin-bottom: 30px; }
        .bar-container { width: 50%; background: #eee; margin-top: 5px; }
        .bar { background: #3498db; height: 20px; }
        .table { width: 100%; border-collapse: collapse; }
        .table th, .table td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        .table th { background-color: #f2f2f2; }
        .overview { display: flex; justify-content: space-between; margin-bottom: 20px; }
        .metric { background: #f8f9fa; padding: 15px; border-radius: 5px; flex: 1; margin: 0 10px; }
    </style>
</head>
<body>
    <h1>Obscura Critical Path Profiling</h1>
"#);
    
    // Calculate total values
    let total_time: Duration = stats.iter().map(|s| s.total_time).sum();
    let total_calls: usize = stats.iter().map(|s| s.call_count).sum();
    let avg_time = if total_calls > 0 {
        total_time / total_calls as u32
    } else {
        Duration::new(0, 0)
    };
    
    // Add overview
    output.push_str(&format!(r#"
    <div class="overview">
        <div class="metric">
            <h3>Total Profile Time</h3>
            <p>{:?}</p>
        </div>
        <div class="metric">
            <h3>Total Operations</h3>
            <p>{}</p>
        </div>
        <div class="metric">
            <h3>Average Operation Time</h3>
            <p>{:?}</p>
        </div>
    </div>
"#, total_time, total_calls, avg_time));
    
    // Group by category
    let mut by_category: HashMap<String, Vec<&ProfileStats>> = HashMap::new();
    for stat in stats {
        by_category.entry(stat.category.clone())
            .or_default()
            .push(stat);
    }
    
    // Generate visualization for each category
    for (category, cat_stats) in by_category.iter() {
        output.push_str(&format!(r#"
    <div class="category">
        <h2>Category: {}</h2>
        <table class="table">
            <thead>
                <tr>
                    <th>Operation</th>
                    <th>Calls</th>
                    <th>Total Time</th>
                    <th>Avg Time</th>
                    <th>% of Total</th>
                    <th>Profile</th>
                </tr>
            </thead>
            <tbody>
"#, category));
        
        // Sort by total time spent (descending)
        let mut sorted_stats = cat_stats.clone();
        sorted_stats.sort_by(|a, b| b.total_time.cmp(&a.total_time));
        
        for stat in sorted_stats {
            let percentage = if total_time.as_nanos() > 0 {
                (stat.total_time.as_nanos() as f64 / total_time.as_nanos() as f64) * 100.0
            } else {
                0.0
            };
            
            output.push_str(&format!(r#"
                <tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td>{:?}</td>
                    <td>{:?}</td>
                    <td>{:.2}%</td>
                    <td>
                        <div class="bar-container">
                            <div class="bar" style="width: {}%;"></div>
                        </div>
                    </td>
                </tr>
"#, stat.name, stat.call_count, stat.total_time, stat.average_time(), percentage, percentage.min(100.0)));
        }
        
        output.push_str(r#"
            </tbody>
        </table>
    </div>
"#);
    }
    
    // HTML footer
    output.push_str(r#"
</body>
</html>
"#);
    
    output
}

/// Generate JSON visualization for external tools
fn generate_json_visualization(stats: &[ProfileStats]) -> io::Result<String> {
    let mut output = Vec::new();
    
    #[derive(serde::Serialize)]
    struct ProfileData {
        name: String,
        category: String,
        call_count: usize,
        total_time_ns: u128,
        min_time_ns: u128,
        max_time_ns: u128,
        avg_time_ns: u128,
        std_dev_ns: u128,
    }
    
    let profile_data: Vec<ProfileData> = stats.iter()
        .map(|stat| {
            ProfileData {
                name: stat.name.clone(),
                category: stat.category.clone(),
                call_count: stat.call_count,
                total_time_ns: stat.total_time.as_nanos(),
                min_time_ns: stat.min_time.as_nanos(),
                max_time_ns: stat.max_time.as_nanos(),
                avg_time_ns: stat.average_time().as_nanos(),
                std_dev_ns: stat.std_deviation().as_nanos(),
            }
        })
        .collect();
    
    serde_json::to_writer_pretty(&mut output, &profile_data)?;
    
    Ok(String::from_utf8_lossy(&output).to_string())
}

/// Generate CSV visualization
fn generate_csv_visualization(stats: &[ProfileStats]) -> String {
    let mut output = String::new();
    
    // CSV header
    output.push_str("Category,Operation,Calls,Total Time (ns),Min Time (ns),Max Time (ns),Avg Time (ns),StdDev (ns)\n");
    
    // Sort by category and then by total time
    let mut sorted_stats = stats.to_vec();
    sorted_stats.sort_by(|a, b| {
        a.category.cmp(&b.category)
            .then_with(|| b.total_time.cmp(&a.total_time))
    });
    
    // Add each stat as a CSV row
    for stat in sorted_stats {
        output.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            stat.category,
            stat.name,
            stat.call_count,
            stat.total_time.as_nanos(),
            stat.min_time.as_nanos(),
            stat.max_time.as_nanos(),
            stat.average_time().as_nanos(),
            stat.std_deviation().as_nanos()
        ));
    }
    
    output
}

/// Generate flame graph format
fn generate_flamegraph_visualization(stats: &[ProfileStats]) -> String {
    let mut output = String::new();
    
    // Sort by category and name for consistent output
    let mut sorted_stats = stats.to_vec();
    sorted_stats.sort_by(|a, b| {
        a.category.cmp(&b.category)
            .then_with(|| a.name.cmp(&b.name))
    });
    
    // Generate flame graph input format (stack;weight)
    for stat in sorted_stats {
        output.push_str(&format!(
            "{};{};{}\n",
            stat.category,
            stat.name,
            stat.total_time.as_micros()
        ));
    }
    
    output
}

/// Print a colored text report to the console
pub fn print_colored_report(stats: &[ProfileStats]) {
    println!("{}", "Critical Path Profile Report".green().bold());
    println!("{}", "===========================".green());
    
    // Calculate total values
    let total_time: Duration = stats.iter().map(|s| s.total_time).sum();
    let total_calls: usize = stats.iter().map(|s| s.call_count).sum();
    
    println!("{}: {:?}", "Total profiled time".cyan().bold(), total_time);
    println!("{}: {}", "Total operations".cyan().bold(), total_calls);
    println!();
    
    // Group by category
    let mut by_category: HashMap<String, Vec<&ProfileStats>> = HashMap::new();
    for stat in stats {
        by_category.entry(stat.category.clone())
            .or_default()
            .push(stat);
    }
    
    // Generate visualization for each category
    for (category, cat_stats) in by_category.iter() {
        println!("{}: {}", "Category".yellow().bold(), category.yellow());
        println!("{}", "=".repeat(category.len() + 9).yellow());
        
        // Sort by total time spent (descending)
        let mut sorted_stats = cat_stats.clone();
        sorted_stats.sort_by(|a, b| b.total_time.cmp(&a.total_time));
        
        // Find the longest operation name for alignment
        let max_name_len = sorted_stats.iter()
            .map(|s| s.name.len())
            .max()
            .unwrap_or(10);
        
        // Print each operation with a bar representing its percentage of time
        for stat in sorted_stats {
            let percentage = if total_time.as_nanos() > 0 {
                (stat.total_time.as_nanos() as f64 / total_time.as_nanos() as f64) * 100.0
            } else {
                0.0
            };
            
            // Color code based on percentage
            let percentage_str = format!("{:>6.2}%", percentage);
            let colored_percentage = if percentage > 30.0 {
                percentage_str.red()
            } else if percentage > 10.0 {
                percentage_str.yellow()
            } else {
                percentage_str.green()
            };
            
            // Create a visual bar
            let bar_length = (percentage as usize).min(50);
            let bar = "#".repeat(bar_length);
            let colored_bar = if percentage > 30.0 {
                bar.red()
            } else if percentage > 10.0 {
                bar.yellow()
            } else {
                bar.green()
            };
            
            println!(
                "{:<width$} | {} | {:?} | {} calls | {}",
                stat.name.white().bold(),
                colored_percentage,
                stat.average_time(),
                stat.call_count.to_string().cyan(),
                colored_bar,
                width = max_name_len
            );
        }
        
        println!();
    }
}

/// Generate a complete visualization and save to files
pub fn generate_full_visualization(
    output_dir: &str,
    categories: Option<Vec<String>>,
) -> io::Result<()> {
    // Create the output directory if it doesn't exist
    let path = Path::new(output_dir);
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    
    // Get all stats from the global profiler
    let stats = GLOBAL_PROFILER.get_all_stats();
    
    // Filter by categories if specified
    let filtered_stats = if let Some(ref cats) = categories {
        stats.into_iter()
            .filter(|s| cats.contains(&s.category))
            .collect::<Vec<_>>()
    } else {
        stats
    };
    
    // Generate all formats
    let formats = [
        (OutputFormat::Html, "profiling_report.html"),
        (OutputFormat::Json, "profiling_data.json"),
        (OutputFormat::Csv, "profiling_data.csv"),
        (OutputFormat::FlameGraph, "profiling_flamegraph.txt"),
    ];
    
    for (format, filename) in formats.iter() {
        let output_path = path.join(filename);
        let _ = generate_visualization(*format, None, Some(output_path.to_str().unwrap()))?;
        println!("Generated {} report: {}", format_name(*format), output_path.display());
    }
    
    // Also print a text report to the console
    print_colored_report(&filtered_stats);
    
    Ok(())
}

/// Get a string representation of the format
fn format_name(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Text => "Text",
        OutputFormat::Html => "HTML",
        OutputFormat::Json => "JSON",
        OutputFormat::Csv => "CSV",
        OutputFormat::FlameGraph => "Flame Graph",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::profiler::{profile, set_profiling_level, ProfilingLevel, reset_profiling_stats};
    use std::thread;
    
    #[test]
    fn test_text_visualization() {
        // Reset profiling stats
        reset_profiling_stats();
        set_profiling_level(ProfilingLevel::Debug);
        
        // Generate some test data
        {
            let _span = profile("op1", "test_category");
            thread::sleep(Duration::from_millis(10));
        }
        {
            let _span = profile("op2", "test_category");
            thread::sleep(Duration::from_millis(20));
        }
        {
            let _span = profile("op3", "different_category");
            thread::sleep(Duration::from_millis(30));
        }
        
        // Get stats
        let stats = GLOBAL_PROFILER.get_all_stats();
        
        // Generate text visualization
        let text = generate_text_visualization(&stats);
        
        // Verify it contains the expected information
        assert!(text.contains("Critical Path Visualization"));
        assert!(text.contains("Category: test_category"));
        assert!(text.contains("Category: different_category"));
        assert!(text.contains("op1"));
        assert!(text.contains("op2"));
        assert!(text.contains("op3"));
    }
    
    #[test]
    fn test_html_visualization() {
        // Reset profiling stats
        reset_profiling_stats();
        set_profiling_level(ProfilingLevel::Debug);
        
        // Generate some test data
        {
            let _span = profile("op1", "test_category");
            thread::sleep(Duration::from_millis(10));
        }
        
        // Get stats
        let stats = GLOBAL_PROFILER.get_all_stats();
        
        // Generate HTML visualization
        let html = generate_html_visualization(&stats);
        
        // Verify it contains the expected HTML elements
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<html"));
        assert!(html.contains("Obscura Critical Path Profiling"));
        assert!(html.contains("test_category"));
        assert!(html.contains("op1"));
    }
    
    #[test]
    fn test_csv_visualization() {
        // Reset profiling stats
        reset_profiling_stats();
        set_profiling_level(ProfilingLevel::Debug);
        
        // Generate some test data
        {
            let _span = profile("op1", "test_category");
            thread::sleep(Duration::from_millis(10));
        }
        
        // Get stats
        let stats = GLOBAL_PROFILER.get_all_stats();
        
        // Generate CSV visualization
        let csv = generate_csv_visualization(&stats);
        
        // Verify it contains the expected CSV format
        assert!(csv.contains("Category,Operation,Calls,Total Time (ns)"));
        assert!(csv.contains("test_category,op1,1,"));
    }
} 